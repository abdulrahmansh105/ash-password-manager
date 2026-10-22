"""Versioned Argon2id/AES-GCM backups with a recoverable password slot.

Version 2 includes the encrypted password slot, never a device slot or
Local Key. Restoring requires the master password in effect at backup time.
Version 1 omitted all slots and cannot restore independently; it requires
an explicitly supplied surviving password slot from the original vault.
"""

from __future__ import annotations

import base64
import io
import json
import os
import secrets
import shutil
import tarfile
import tempfile
import time
from pathlib import Path

from ..crypto.aead import AeadError, NONCE_LEN, TAG_LEN, SealedBox, open_box, seal
from ..crypto.kdf import Argon2Params, derive_key_argon2id
from ..crypto.keyslots import KeySlot, SlotFormatError, SlotKind
from ..security.memory import SecretBytes
from ..vaults import health
from ..vaults.layout import VaultLayout

ARCHIVE_VERSION = 2
ARCHIVE_SUFFIX = ".ashbak"
_LEGACY_NAMES = ("Passwords.kdbx", "Key.key", "vault.json", "devices.json")
_BUNDLED_NAMES = (*_LEGACY_NAMES, "keyslots/password.slot")
_HEADER_LEN_BYTES = 4
MAX_HEADER_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


class BackupError(Exception):
    """A backup operation failed; messages never include secret content."""


class BackupCorruptError(BackupError):
    """Malformed, incomplete, oversized, or foreign backup."""


class BackupWrongPassphraseError(BackupError):
    """Wrong passphrase and authenticated corruption are indistinguishable."""


def _aad(version: int = ARCHIVE_VERSION) -> bytes:
    return f"ash-pm/backup/v{version}".encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), altchars=b"-_", validate=True)


def _zero(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def backup_filename(vault_name: str) -> str:
    safe_name = (
        "".join(c if c.isalnum() or c in "-_" else "-" for c in vault_name) or "vault"
    )
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"ash-backup-{safe_name[:80]}-{stamp}{ARCHIVE_SUFFIX}"


def _validate_slot(raw: bytes, vault_raw: bytes) -> None:
    try:
        slot = KeySlot.from_dict(json.loads(raw))
        vault = json.loads(vault_raw)
        if (
            slot.kind is not SlotKind.PASSWORD
            or slot.slot_id != "password"
            or slot.vault_id != vault["vault_id"]
        ):
            raise ValueError("Slot identity mismatch")
    except (
        SlotFormatError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        UnicodeError,
    ) as exc:
        raise BackupCorruptError(
            "Backup password slot or vault metadata is invalid."
        ) from exc


def _validate_payload(data: bytes, version: int) -> dict[str, bytes]:
    """Use the same complete validation for verify and restore, before writes."""
    expected = set(_BUNDLED_NAMES if version == 2 else _LEGACY_NAMES)
    try:
        files = {}
        # Only our uncompressed tar format is accepted (no decompression bombs).
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
            for member in tar:
                if (
                    member.name not in expected
                    or member.name in files
                    or not member.isfile()
                    or member.issparse()
                ):
                    raise BackupCorruptError(
                        "Backup contains unexpected, duplicate, or non-regular entries."
                    )
                if (
                    not 0 < member.size <= MAX_ARCHIVE_BYTES
                    or sum(map(len, files.values())) + member.size > MAX_ARCHIVE_BYTES
                ):
                    raise BackupCorruptError("Backup member size is invalid.")
                stream = tar.extractfile(member)
                if stream is None:
                    raise BackupCorruptError("Backup member is unreadable.")
                files[member.name] = stream.read()
                if len(files[member.name]) != member.size:
                    raise BackupCorruptError("Backup member is truncated.")
        if set(files) != expected:
            raise BackupCorruptError("Backup is missing required files.")
        vault = json.loads(files["vault.json"])
        devices = json.loads(files["devices.json"])
        if (
            not isinstance(vault, dict)
            or not isinstance(vault.get("vault_id"), str)
            or not vault["vault_id"]
        ):
            raise BackupCorruptError("Backup vault metadata is invalid.")
        if not isinstance(devices, list) or any(
            not isinstance(item, dict) for item in devices
        ):
            raise BackupCorruptError("Backup device roster is invalid.")
        if version == 2:
            _validate_slot(files["keyslots/password.slot"], files["vault.json"])
        return files
    except BackupError:
        raise
    except (tarfile.TarError, OSError, ValueError, UnicodeError) as exc:
        raise BackupCorruptError("Backup payload is malformed.") from exc


def _pack(layout: VaultLayout) -> bytes:
    buf = io.BytesIO()
    paths = {
        "Passwords.kdbx": layout.kdbx_path,
        "Key.key": layout.keyfile_path,
        "vault.json": layout.vault_json,
        "devices.json": layout.devices_json,
        "keyslots/password.slot": layout.keyslot_path("password"),
    }
    try:
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for arcname, path in paths.items():
                if not path.is_file() or path.is_symlink():
                    raise BackupError(
                        f"Cannot back up: missing or unsafe file {path.name}."
                    )
                if path.stat().st_size > MAX_ARCHIVE_BYTES:
                    raise BackupError("Vault exceeds the supported backup size.")
                tar.add(path, arcname=arcname, recursive=False)
        payload = buf.getvalue()
        if len(payload) > MAX_ARCHIVE_BYTES:
            raise BackupError("Vault exceeds the supported backup size.")
        _validate_payload(payload, ARCHIVE_VERSION)
        return payload
    except OSError as exc:
        raise BackupError(f"Could not read vault files: {type(exc).__name__}.") from exc


def create_backup(
    layout: VaultLayout,
    output_path: Path,
    passphrase: SecretBytes,
    *,
    params: Argon2Params | None = None,
) -> Path:
    if output_path.exists():
        raise BackupError(f"Refusing to overwrite an existing file: {output_path}")
    if not passphrase:
        raise BackupError("A non-empty backup passphrase is required.")
    params = params or Argon2Params()
    payload = _pack(layout)
    salt = secrets.token_bytes(16)
    kek = bytearray(derive_key_argon2id(passphrase, salt, params))
    try:
        box = seal(bytes(kek), payload, aad=_aad())
    finally:
        _zero(kek)
    header = json.dumps(
        {
            "version": ARCHIVE_VERSION,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "argon2": params.to_dict(),
            "salt": _b64(salt),
            "nonce": _b64(box.nonce),
            "tag": _b64(box.tag),
        }
    ).encode("utf-8")
    created = False
    try:
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "wb") as fh:
            fh.write(len(header).to_bytes(_HEADER_LEN_BYTES, "big"))
            fh.write(header)
            fh.write(box.ciphertext)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        if created:
            output_path.unlink(missing_ok=True)
        raise BackupError(f"Could not write backup: {type(exc).__name__}.") from exc
    return output_path


def _decrypt_archive(archive_path: Path, passphrase: SecretBytes) -> tuple[bytes, int]:
    try:
        with archive_path.open("rb") as fh:
            prefix = fh.read(_HEADER_LEN_BYTES)
            if len(prefix) != _HEADER_LEN_BYTES:
                raise BackupCorruptError("Backup file is too short.")
            header_len = int.from_bytes(prefix, "big")
            if not 0 < header_len <= MAX_HEADER_BYTES:
                raise BackupCorruptError("Backup header size is invalid.")
            header = fh.read(header_len)
            if len(header) != header_len:
                raise BackupCorruptError("Backup file is truncated.")
            ciphertext = fh.read(MAX_ARCHIVE_BYTES + 1)
            if not ciphertext or len(ciphertext) > MAX_ARCHIVE_BYTES:
                raise BackupCorruptError("Backup payload size is invalid.")
    except OSError as exc:
        raise BackupError(f"Could not read backup file: {type(exc).__name__}.") from exc
    try:
        manifest = json.loads(header)
        version = manifest["version"]
        if type(version) is not int or version not in (1, 2):
            raise ValueError("Unsupported version")
        params = Argon2Params.from_dict(manifest["argon2"])
        salt = _unb64(manifest["salt"])
        box = SealedBox(
            nonce=_unb64(manifest["nonce"]),
            ciphertext=ciphertext,
            tag=_unb64(manifest["tag"]),
        )
        if (
            not 16 <= len(salt) <= 64
            or len(box.nonce) != NONCE_LEN
            or len(box.tag) != TAG_LEN
        ):
            raise ValueError("Invalid encryption metadata")
    except (KeyError, ValueError, TypeError, AttributeError, UnicodeError) as exc:
        raise BackupCorruptError("Backup header is malformed or unsupported.") from exc
    kek = bytearray(derive_key_argon2id(passphrase, salt, params))
    try:
        return open_box(bytes(kek), box, aad=_aad(version)), version
    except AeadError as exc:
        raise BackupWrongPassphraseError(
            "Incorrect backup passphrase, or the backup file is corrupted."
        ) from exc
    finally:
        _zero(kek)


def verify_backup(archive_path: Path, passphrase: SecretBytes) -> bool:
    """Validate a complete, independently recoverable backup without writes.

    Version 1 is deliberately not reported as recoverable: it needs a
    surviving original password slot and must be restored explicitly.
    """
    payload, version = _decrypt_archive(archive_path, passphrase)
    _validate_payload(payload, version)
    if version == 1:
        raise BackupError(
            "Legacy version-1 backup omits the password slot and is not independently recoverable. "
            "Restore requires --legacy-password-slot from the original vault; create a new backup if possible."
        )
    return True


def restore_backup(
    archive_path: Path,
    destination: VaultLayout,
    passphrase: SecretBytes,
    *,
    legacy_password_slot: Path | None = None,
) -> None:
    if destination.container_dir.exists() and any(destination.container_dir.iterdir()):
        raise BackupError(
            f"Refusing to restore into a non-empty directory: {destination.container_dir}"
        )
    payload, version = _decrypt_archive(archive_path, passphrase)
    files = _validate_payload(payload, version)
    if version == 1:
        if legacy_password_slot is None:
            raise BackupError(
                "Legacy version-1 backup has no password slot. Supply --legacy-password-slot "
                "from the original vault; the backup alone cannot recover its encryption key."
            )
        try:
            raw = legacy_password_slot.read_bytes()
        except OSError as exc:
            raise BackupError("Could not read the original password slot.") from exc
        _validate_slot(raw, files["vault.json"])
        files["keyslots/password.slot"] = raw
    elif legacy_password_slot is not None:
        raise BackupError(
            "An external password slot is only accepted for version-1 backups."
        )

    # No tar extraction: validated bytes are written under fixed names in a
    # private sibling directory, then published in one rename on success.
    destination.container_dir.parent.mkdir(parents=True, exist_ok=True)
    work = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.container_dir.name}.restore-",
            dir=destination.container_dir.parent,
        )
    )
    try:
        for name, contents in files.items():
            path = work / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(contents)
                fh.flush()
                os.fsync(fh.fileno())
        health.update_integrity_manifest(VaultLayout(work))
        os.replace(work, destination.container_dir)
    except OSError as exc:
        raise BackupError(f"Could not restore backup: {type(exc).__name__}.") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
