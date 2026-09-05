"""KeePassXC-compatible KDBX vault access -- the isolated compatibility
layer. This is the *only* module in the application that imports
``pykeepass`` or knows anything about the KDBX file format. Everything
above this layer (accounts repository, auth engine, UI) talks to
``AccountSummary``/``AccountSecrets`` and never touches pykeepass
directly, so if the underlying library or file format ever needs to
change, this is the only file that moves.

KeePassXC remains the source of truth (spec section 27): every field this
module writes is either a standard KDBX field (title, username, password,
url, notes, tags) or a KeePassXC-recognized convention (the ``otp``
custom string holding an ``otpauth://`` URI, exactly what KeePassXC's own
"Set up TOTP" dialog writes) -- opening the same file in KeePassXC shows
correct values for all of those. The few fields with no KeePassXC-native
equivalent are namespaced custom strings prefixed ``PM_`` so they're
visibly application-specific rather than colliding with anything
KeePassXC or another tool might use:

    PM_ServiceName      unprotected  short service/site label (distinct from Title)
    PM_AppIdentifiers   unprotected  JSON list of window-class/title match patterns
    PM_AuthStrategy     unprotected  JSON login-strategy steps (no secrets)
    PM_IconRef          unprotected  filename of a cached icon under the USB's icon cache dir
    PM_RecoveryCodes    protected    JSON list of {code, used, label}

Mapping of spec-required fields to KDBX fields:
    Account display name  -> Title           (KeePassXC's own primary label)
    Service / site name   -> PM_ServiceName
    Username / email      -> Username
    Password               -> Password (protected, KDBX inner-stream encrypted)
    Website / service URL -> URL
    Notes                  -> Notes
    TOTP                   -> otp custom string (protected), otpauth:// URI
    Recovery codes          -> PM_RecoveryCodes (protected)
    Tags                    -> native KDBX4 Tags
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid as uuid_mod
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from ..recovery.codes import deserialize as deserialize_recovery_codes
from ..recovery.codes import serialize as serialize_recovery_codes
from ..security.memory import SecretBytes
from ..totp.totp import TotpConfig
from .models import AccountSecrets, AccountSummary, RecoveryCode, normalize_category

PM_SERVICE_NAME = "PM_ServiceName"
PM_APP_IDENTIFIERS = "PM_AppIdentifiers"
PM_AUTH_STRATEGY = "PM_AuthStrategy"
PM_ICON_REF = "PM_IconRef"
PM_RECOVERY_CODES = "PM_RecoveryCodes"
PM_CATEGORY = "PM_Category"
OTP_FIELD = "otp"


class VaultError(Exception):
    """Base class for vault-layer errors. Messages never contain secret
    material -- only file paths, entry titles, and generic causes."""


class VaultOpenError(VaultError):
    """Raised when the vault cannot be opened (wrong password/key file,
    missing file, corrupt database)."""


class EntryNotFoundError(VaultError):
    pass


def _require_pykeepass():
    try:
        import pykeepass  # noqa: F401
        return pykeepass
    except ImportError as exc:
        raise VaultError(
            "pykeepass is not installed. Install the 'python-pykeepass' "
            "package (pacman -S python-pykeepass) or 'pip install pykeepass'."
        ) from exc


def _totp_to_uri(config: TotpConfig, label: str, issuer: str) -> str:
    params = {
        "secret": config.secret_base32.rstrip("="),
        "digits": str(config.digits),
        "period": str(config.period),
        "algorithm": config.algorithm,
        "issuer": issuer,
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"otpauth://totp/{quote(label)}?{query}"


def _remove_reserved_string_field(entry, key: str) -> None:
    """Remove a string field whose name is on pykeepass's ``reserved_keys``
    list (e.g. ``otp``), which ``Entry.delete_custom_property`` refuses
    to touch. Mirrors that method's own implementation, minus the
    reserved-key assertion -- there is no public API for this because
    reserved fields normally have their own dedicated property (like
    ``Entry.otp``), which has a setter but no "unset" operation."""
    prop = entry._xpath(f'String/Key[text()="{key}"]/..', first=True)
    if prop is not None:
        entry._element.remove(prop)


def _totp_from_uri(uri: str) -> TotpConfig | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme != "otpauth":
            return None
        qs = parse_qs(parsed.query)
        secret = qs.get("secret", [None])[0]
        if not secret:
            return None
        digits = int(qs.get("digits", ["6"])[0])
        period = int(qs.get("period", ["30"])[0])
        algorithm = qs.get("algorithm", ["SHA1"])[0].upper()
        return TotpConfig(secret_base32=secret, digits=digits, period=period, algorithm=algorithm)
    except (ValueError, IndexError, KeyError):
        return None


@dataclass
class VaultHandle:
    """Wraps an open ``pykeepass.PyKeePass`` instance. Construct via
    ``open_vault()``; never instantiate directly."""

    _kp: object  # pykeepass.PyKeePass, kept untyped to avoid importing
    # pykeepass at module import time for callers that only need the
    # dataclass/type surface (e.g. tests that mock this out).

    # -- reading -----------------------------------------------------

    def list_account_summaries(self) -> list[AccountSummary]:
        summaries = []
        for entry in self._kp.entries:
            summaries.append(self._to_summary(entry))
        return summaries

    def get_app_identifiers(self, entry_uuid: str) -> tuple[str, ...]:
        """App-identifier match patterns only (non-secret; used by the
        Auto-Type strategy editor's "Test Strategy" action so it can run
        real target detection without ever constructing a real
        ``AccountSecrets`` -- i.e. without touching the account's actual
        password/TOTP at all, even transiently)."""
        entry = self._find(entry_uuid)
        raw = entry.get_custom_property(PM_APP_IDENTIFIERS) or "[]"
        try:
            return tuple(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            return ()

    def get_auth_strategy_json(self, entry_uuid: str) -> str | None:
        """The stored strategy JSON only -- same non-secret rationale as
        ``get_app_identifiers``."""
        entry = self._find(entry_uuid)
        return entry.get_custom_property(PM_AUTH_STRATEGY)

    def get_account_secrets(self, entry_uuid: str) -> AccountSecrets:
        entry = self._find(entry_uuid)
        app_ids_raw = entry.get_custom_property(PM_APP_IDENTIFIERS) or "[]"
        try:
            app_ids = tuple(json.loads(app_ids_raw))
        except (json.JSONDecodeError, TypeError):
            app_ids = ()

        otp_uri = entry.otp
        totp = _totp_from_uri(otp_uri) if otp_uri else None

        codes_raw = entry.get_custom_property(PM_RECOVERY_CODES)
        codes = deserialize_recovery_codes(codes_raw)

        return AccountSecrets(
            entry_uuid=str(entry.uuid),
            display_name=entry.title or "",
            service_name=entry.get_custom_property(PM_SERVICE_NAME) or "",
            username=entry.username or "",
            password=SecretBytes(entry.password or ""),
            url=entry.url or "",
            notes=entry.notes or "",
            app_identifiers=app_ids,
            auth_strategy_json=entry.get_custom_property(PM_AUTH_STRATEGY),
            totp=totp,
            recovery_codes=codes,
            category=normalize_category(entry.get_custom_property(PM_CATEGORY)),
        )

    def _to_summary(self, entry) -> AccountSummary:
        tags = tuple(entry.tags) if entry.tags else ()
        return AccountSummary(
            entry_uuid=str(entry.uuid),
            display_name=entry.title or "",
            service_name=entry.get_custom_property(PM_SERVICE_NAME) or "",
            icon_ref=entry.get_custom_property(PM_ICON_REF),
            tags=tags,
            has_totp=bool(entry.otp),
            has_recovery_codes=bool(entry.get_custom_property(PM_RECOVERY_CODES)),
            has_username=bool(entry.username),
            has_password=bool(entry.password),
            category=normalize_category(entry.get_custom_property(PM_CATEGORY)),
        )

    def _find(self, entry_uuid: str):
        entry = self._kp.find_entries(uuid=uuid_mod.UUID(entry_uuid), first=True)
        if entry is None:
            raise EntryNotFoundError(f"No entry with uuid {entry_uuid}")
        return entry

    # -- writing -------------------------------------------------------

    def create_account(
        self,
        display_name: str,
        service_name: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        app_identifiers: list[str] | None = None,
        tags: list[str] | None = None,
        auth_strategy_json: str | None = None,
        category: str = "logins",
    ) -> str:
        entry = self._kp.add_entry(
            self._kp.root_group,
            title=display_name,
            username=username,
            password=password,
            url=url or "",
            notes=notes or "",
        )
        entry.set_custom_property(PM_SERVICE_NAME, service_name or "")
        entry.set_custom_property(PM_APP_IDENTIFIERS, json.dumps(app_identifiers or []))
        entry.set_custom_property(PM_CATEGORY, normalize_category(category))
        if auth_strategy_json:
            entry.set_custom_property(PM_AUTH_STRATEGY, auth_strategy_json)
        if tags:
            entry.tags = list(tags)
        return str(entry.uuid)

    def update_account_fields(self, entry_uuid: str, **fields: str) -> None:
        """Update plain (non-secret-schema) fields: display_name,
        service_name, username, password, url, notes, auth_strategy_json."""
        entry = self._find(entry_uuid)
        if "display_name" in fields:
            entry.title = fields["display_name"]
        if "service_name" in fields:
            entry.set_custom_property(PM_SERVICE_NAME, fields["service_name"])
        if "username" in fields:
            entry.username = fields["username"]
        if "password" in fields:
            entry.password = fields["password"]
        if "url" in fields:
            entry.url = fields["url"]
        if "notes" in fields:
            entry.notes = fields["notes"]
        if "auth_strategy_json" in fields:
            entry.set_custom_property(PM_AUTH_STRATEGY, fields["auth_strategy_json"])
        if "app_identifiers" in fields:
            entry.set_custom_property(PM_APP_IDENTIFIERS, fields["app_identifiers"])
        if "category" in fields:
            entry.set_custom_property(PM_CATEGORY, normalize_category(fields["category"]))

    def set_totp(self, entry_uuid: str, config: TotpConfig, issuer: str = "") -> None:
        # `otp` is a KeePassXC/pykeepass *reserved* field name (it has its
        # own dedicated property, not the generic custom-property API)
        # precisely because it's the de facto standard KeePassXC itself
        # uses -- assigning entry.otp is what keeps this vault readable
        # by KeePassXC with correct TOTP codes, not an app-specific
        # workaround.
        entry = self._find(entry_uuid)
        label = f"{issuer or entry.title}:{entry.username or ''}"
        uri = _totp_to_uri(config, label=label, issuer=issuer or entry.title or "")
        entry.otp = uri

    def remove_totp(self, entry_uuid: str) -> None:
        entry = self._find(entry_uuid)
        _remove_reserved_string_field(entry, OTP_FIELD)

    def set_recovery_codes(self, entry_uuid: str, codes: list[RecoveryCode]) -> None:
        entry = self._find(entry_uuid)
        entry.set_custom_property(PM_RECOVERY_CODES, serialize_recovery_codes(codes), protect=True)

    def remove_recovery_codes(self, entry_uuid: str) -> None:
        entry = self._find(entry_uuid)
        if entry.get_custom_property(PM_RECOVERY_CODES) is not None:
            entry.delete_custom_property(PM_RECOVERY_CODES)

    def set_icon_ref(self, entry_uuid: str, icon_ref: str) -> None:
        entry = self._find(entry_uuid)
        entry.set_custom_property(PM_ICON_REF, icon_ref)

    def delete_account(self, entry_uuid: str) -> None:
        entry = self._find(entry_uuid)
        entry.delete()

    def rekey(self, *, password: str | None = None, keyfile: str | None = None) -> None:
        """Change the vault's own KDBX credentials in place. Used only
        by ``core.vault.provisioning`` when adopting a pre-existing
        vault into the ASH key-slot model (spec sections 13/14): the
        KDBX's real password becomes a random Vault Master Secret,
        wrapped afterwards in the master-password and per-device key
        slots (see ``core.crypto.keyslots``) -- this method only
        performs the underlying pykeepass credential change. Does not
        call ``save()``; the caller decides when to persist."""
        if password is not None:
            self._kp.password = password
        if keyfile is not None:
            self._kp.keyfile = keyfile

    def save(self) -> None:
        self._kp.save()

    def close(self) -> None:
        """Drop the reference to the underlying database. CPython/
        pykeepass give no guaranteed secure-erase of the decrypted
        in-memory tree (see core.security.memory docstring for the same
        honest limitation) -- this makes prior data eligible for GC
        promptly, which is the practical best available here."""
        self._kp = None


def open_vault(vault_path: Path, key_file_path: Path | None, password: SecretBytes | None) -> VaultHandle:
    """Open a KDBX vault. At least one of ``key_file_path``/``password``
    must be provided (this project's chosen configuration is Key File
    only, per spec section 2, but both are supported since KeePassXC
    databases may use either or both).

    Raises ``VaultOpenError`` on any failure (missing file, wrong
    key/password, corrupt database) -- never partially returns a handle.
    """
    pykeepass = _require_pykeepass()
    if not vault_path.exists():
        raise VaultOpenError(f"Vault file not found: {vault_path}")
    if key_file_path is not None and not key_file_path.exists():
        raise VaultOpenError(f"Key file not found: {key_file_path}")

    kwargs: dict = {}
    if key_file_path is not None:
        kwargs["keyfile"] = str(key_file_path)
    if password is not None:
        kwargs["password"] = password.to_str()

    try:
        kp = pykeepass.PyKeePass(str(vault_path), **kwargs)
    except Exception as exc:  # noqa: BLE001 - pykeepass raises several distinct types
        raise VaultOpenError(f"Failed to open vault: {type(exc).__name__}") from exc
    finally:
        if password is not None:
            password.wipe()

    return VaultHandle(_kp=kp)


def generate_keyfile(path: Path) -> None:
    """Write a KeePass 2.x XML "Version 2.0" key file -- the same format
    KeePassXC's own "Create Key File" writes -- so vaults created here
    remain fully KeePassXC-compatible. pykeepass (like KeePassXC) expects
    the keyfile to already exist; it never generates one itself.

    32 random bytes from ``secrets`` (CSPRNG), hex-encoded, with the
    4-byte SHA-256 integrity prefix the format requires. Written with
    0600 permissions from creation (no world/group-readable window).
    """
    key_bytes = secrets.token_bytes(32)
    hex_data = key_bytes.hex().upper()
    check_hash = hashlib.sha256(key_bytes).digest()[:4].hex().upper()
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<KeyFile>\n"
        "\t<Meta>\n"
        "\t\t<Version>2.0</Version>\n"
        "\t</Meta>\n"
        "\t<Key>\n"
        f'\t\t<Data Hash="{check_hash}">{hex_data}</Data>\n'
        "\t</Key>\n"
        "</KeyFile>\n"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(xml)


# KDBX4 KDF UUIDs, as defined by the KeePass format and used verbatim by
# KeePassXC. These are the same 16-byte values pykeepass's own reader
# (pykeepass.kdbx_parsing.kdbx4.kdf_uuids) uses to decide Argon2d vs.
# Argon2id when *reading* -- see the upgrade note in create_vault() for
# why this module also uses them when *writing*.
_KDF_UUID_ARGON2D = b"\xefcm\xdf\x8c)DK\x91\xf7\xa9\xa4\x03\xe3\n\x0c"
_KDF_UUID_ARGON2ID = b"\x9e)\x8b\x19V\xdbGs\xb2=\xfc>\xc6\xf0\xa1\xe6"


class KdfUpgradeError(VaultError):
    """Raised if the installed pykeepass's internal header structure no
    longer matches what ``_upgrade_kdf_to_argon2id`` expects. Callers
    must not catch this and silently proceed with Argon2d -- see
    create_vault()'s docstring: correctness over silent downgrade."""


def _upgrade_kdf_to_argon2id(kp) -> None:
    """Rewrite a freshly created database's KDF from pykeepass's default
    (Argon2d) to Argon2id, in place, before the first save.

    Why this is safe: KDBX4's Argon2d and Argon2id parameter blocks have
    an *identical* shape (salt, iterations, memory, parallelism, version)
    -- only the ``$UUID`` value differs, selecting which Argon2 variant
    the KDF-computation code path uses (pykeepass's own reader already
    branches on exactly this UUID: ``Type.ID`` vs. ``Type.D``, see
    ``pykeepass.kdbx_parsing.kdbx4.compute_transformed``). Verified
    end-to-end against the installed pykeepass: create -> swap UUID ->
    save -> reopen -> ``kdf_algorithm`` reports ``"argon2id"`` and all
    entry data round-trips correctly.

    This directly satisfies "do not silently downgrade to Argon2d, and
    do not fabricate Argon2id support that doesn't work": if pykeepass's
    internal structure ever changes shape (a future major version), the
    lookup below raises ``KdfUpgradeError`` instead of silently leaving
    the database on Argon2d.
    """
    try:
        kdf_dict = kp.kdbx["header"]["value"]["dynamic_header"]["kdf_parameters"]["data"]["dict"]
        current_uuid = kdf_dict["$UUID"]["value"]
    except (KeyError, TypeError) as exc:
        raise KdfUpgradeError(
            "Could not locate KDF parameters in the newly created database "
            "(pykeepass internal structure mismatch) -- refusing to silently "
            "leave the vault on Argon2d. See core/vault/kdbx.py."
        ) from exc

    if current_uuid == _KDF_UUID_ARGON2ID:
        return  # already Argon2id (a future pykeepass version might default to it)
    if current_uuid != _KDF_UUID_ARGON2D:
        raise KdfUpgradeError(
            "Newly created database uses an unrecognized KDF -- refusing to "
            "guess. See core/vault/kdbx.py."
        )
    kdf_dict["$UUID"]["value"] = _KDF_UUID_ARGON2ID


def create_vault(vault_path: Path, key_file_path: Path, password: SecretBytes | None = None) -> VaultHandle:
    """Create a new, empty KDBX4 vault plus a matching key file (if
    ``key_file_path`` doesn't already exist -- an existing key file is
    reused as-is, never overwritten). Used by
    ``demo/create_demo_vault.py`` and by the first-run setup flow.

    Uses **Argon2id** (KeePassXC's own current default for new
    databases), not pykeepass's raw default (Argon2d) -- see
    ``_upgrade_kdf_to_argon2id`` above for exactly how and why this is
    safe, and why a structural mismatch raises loudly instead of
    silently keeping Argon2d."""
    pykeepass = _require_pykeepass()
    if not key_file_path.exists():
        generate_keyfile(key_file_path)
    kwargs: dict = {"keyfile": str(key_file_path)}
    if password is not None:
        kwargs["password"] = password.to_str()
    try:
        kp = pykeepass.create_database(str(vault_path), **kwargs)
        _upgrade_kdf_to_argon2id(kp)
        kp.save()
    finally:
        if password is not None:
            password.wipe()
    return VaultHandle(_kp=kp)
