"""Encrypted vault backup/restore (spec section 15).

A backup bundles exactly four files -- the KDBX itself, ``Key.key``,
``vault.json``, and ``devices.json`` -- into one Argon2id/AES-256-GCM
encrypted archive. Deliberately excluded:

  * Every key SLOT (``password.slot``, ``device-*.slot``) -- device
    slots are device-bound and meaningless once restored elsewhere;
    the password slot is trivially regenerated on restore from the
    master password supplied at that time, so a backup made before a
    password change still restores correctly with the *current*
    password, never a stale one.
  * The Local Key file itself -- it never leaves the device it was
    generated on, backup or not (spec section 19).
  * The Vault Master Secret, in any form.

Restoring always re-derives a fresh VMS and a fresh password slot from
the master password supplied at restore time, and always registers
the restoring device as a brand-new device -- a backup is not a way
to transplant a specific device's identity, and restoring never
requires (or accepts) a Local Key.
"""

from __future__ import annotations

import base64
import io
import json
import os
import secrets
import tarfile
import time
from pathlib import Path

from ..crypto.aead import AeadError, SealedBox, open_box, seal
from ..crypto.kdf import Argon2Params, derive_key_argon2id
from ..security.memory import SecretBytes
from ..vaults.layout import VaultLayout

ARCHIVE_VERSION = 1
ARCHIVE_SUFFIX = ".ashbak"
_BUNDLED_NAMES = ("Passwords.kdbx", "Key.key", "vault.json", "devices.json")
_HEADER_LEN_BYTES = 4


class BackupError(Exception):
    pass


class BackupCorruptError(BackupError):
    """Truncated file, bad header JSON, or a tar entry outside the
    expected bundled-file set. Never a partial write is a backup that
    was truly created by this module -- always a corrupted/tampered/
    foreign file."""


class BackupWrongPassphraseError(BackupError):
    """Indistinguishable, deliberately, from "the file is corrupted"
    at the AEAD layer (spec section 21) -- this subclass exists only
    for a slightly more helpful UI message, not because the two cases
    are cryptographically distinguishable."""


def _aad() -> bytes:
    return f"ash-pm/backup/v{ARCHIVE_VERSION}".encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def _zero(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def backup_filename(vault_name: str) -> str:
    safe_name = "".join(c if c.isalnum() or c in "-_" else "-" for c in vault_name) or "vault"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"ash-backup-{safe_name}-{stamp}{ARCHIVE_SUFFIX}"


def _pack(layout: VaultLayout) -> bytes:
    buf = io.BytesIO()
    paths = {
        "Passwords.kdbx": layout.kdbx_path,
        "Key.key": layout.keyfile_path,
        "vault.json": layout.vault_json,
        "devices.json": layout.devices_json,
    }
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for arcname, path in paths.items():
            if not path.exists():
                raise BackupError(f"Cannot back up -- missing required file: {path.name}")
            tar.add(path, arcname=arcname)
    return buf.getvalue()


def _unpack(data: bytes, destination: VaultLayout) -> None:
    destination.ensure_dirs()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
        names = set(tar.getnames())
        if not names.issubset(set(_BUNDLED_NAMES)):
            raise BackupCorruptError("Backup archive contains unexpected entries.")
        for member in tar.getmembers():
            if not member.isfile():
                raise BackupCorruptError("Backup archive contains a non-regular-file entry.")
        # filter="data" additionally rejects path traversal / absolute
        # paths / device files at the extraction layer itself -- the
        # explicit name check above is defense in depth, not a
        # substitute for it.
        tar.extractall(path=destination.container_dir, filter="data")


def create_backup(
    layout: VaultLayout,
    output_path: Path,
    passphrase: SecretBytes,
    *,
    params: Argon2Params | None = None,
) -> Path:
    if output_path.exists():
        raise BackupError(f"Refusing to overwrite an existing file: {output_path}")
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

    try:
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise BackupError(f"Refusing to overwrite an existing file: {output_path}") from exc
    with os.fdopen(fd, "wb") as fh:
        fh.write(len(header).to_bytes(_HEADER_LEN_BYTES, "big"))
        fh.write(header)
        fh.write(box.ciphertext)
    return output_path


def _decrypt_archive(archive_path: Path, passphrase: SecretBytes) -> bytes:
    try:
        raw = archive_path.read_bytes()
    except OSError as exc:
        raise BackupError(f"Could not read backup file: {type(exc).__name__}") from exc

    if len(raw) < _HEADER_LEN_BYTES:
        raise BackupCorruptError("Backup file is too short to be valid.")
    header_len = int.from_bytes(raw[:_HEADER_LEN_BYTES], "big")
    if len(raw) < _HEADER_LEN_BYTES + header_len:
        raise BackupCorruptError("Backup file is truncated.")

    try:
        manifest = json.loads(raw[_HEADER_LEN_BYTES : _HEADER_LEN_BYTES + header_len].decode("utf-8"))
        if manifest.get("version") != ARCHIVE_VERSION:
            raise BackupCorruptError(f"Unsupported backup version: {manifest.get('version')!r}")
        params = Argon2Params.from_dict(manifest["argon2"])
        salt = _unb64(manifest["salt"])
        box = SealedBox(
            nonce=_unb64(manifest["nonce"]),
            ciphertext=raw[_HEADER_LEN_BYTES + header_len :],
            tag=_unb64(manifest["tag"]),
        )
    except BackupCorruptError:
        raise
    except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupCorruptError(f"Malformed backup header: {type(exc).__name__}") from exc

    kek = bytearray(derive_key_argon2id(passphrase, salt, params))
    try:
        return open_box(bytes(kek), box, aad=_aad())
    except AeadError as exc:
        raise BackupWrongPassphraseError("Incorrect backup passphrase, or the backup file is corrupted.") from exc
    finally:
        _zero(kek)


def verify_backup(archive_path: Path, passphrase: SecretBytes) -> bool:
    """Decrypts and validates the archive without writing anything to
    disk -- confirms the passphrase is correct and the bundle is
    well-formed. Raises on any problem; returns True only on a fully
    valid backup."""
    payload = _decrypt_archive(archive_path, passphrase)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r") as tar:
        names = set(tar.getnames())
        if not names.issubset(set(_BUNDLED_NAMES)):
            raise BackupCorruptError("Backup archive contains unexpected entries.")
    return True


def restore_backup(archive_path: Path, destination: VaultLayout, passphrase: SecretBytes) -> None:
    if destination.container_dir.exists() and any(destination.container_dir.iterdir()):
        raise BackupError(f"Refusing to restore into a non-empty directory: {destination.container_dir}")
    payload = _decrypt_archive(archive_path, passphrase)
    _unpack(payload, destination)
