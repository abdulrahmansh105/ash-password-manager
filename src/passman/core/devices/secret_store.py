"""Optional OS secret-store integration for an extra "pepper" mixed
into a device slot's key derivation (spec section 4: "preferably use
the Linux system secret store where practical, while keeping the
actual architecture robust even if that store is unavailable").

Tiering is explicit rather than silently degraded:

  SECRET_SERVICE -- a pepper is stored in the user's Secret Service
                    (GNOME Keyring / KWallet / any libsecret provider)
                    and mixed into the device slot's KDF input. An
                    attacker who copies only the key *file* off disk
                    does not get this pepper.
  FILE_ONLY      -- no Secret Service is reachable; the device slot is
                    protected by the 0600 key file and device binding
                    alone. Still fully functional, just one layer
                    lighter -- surfaced to the user in Settings ->
                    Security, never hidden.

This project's own development machine has the libsecret GI typelib
available but no Secret Service daemon activatable (`gnome-keyring`
absent, `kwalletd6` present but not running as one) -- so FILE_ONLY is
the default-exercised path here, and SECRET_SERVICE activates
automatically the moment a real one is reachable.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from enum import Enum

from ..security.memory import SecretBytes

SCHEMA_NAME = "dev.ash.PasswordManager.LocalKeyPepper"
PEPPER_LEN = 32


class ProtectionTier(str, Enum):
    SECRET_SERVICE = "secret_service"
    FILE_ONLY = "file_only"


def _try_import_secret():
    try:
        import gi

        gi.require_version("Secret", "1")
        from gi.repository import Secret

        return Secret
    except (ImportError, ValueError):
        return None


def _schema(secret_module):
    return secret_module.Schema.new(
        SCHEMA_NAME,
        secret_module.SchemaFlags.NONE,
        {
            "vault_id": secret_module.SchemaAttributeType.STRING,
            "device_id": secret_module.SchemaAttributeType.STRING,
            "kind": secret_module.SchemaAttributeType.STRING,
        },
    )


def _attributes(vault_id: str, device_id: str) -> dict[str, str]:
    return {"vault_id": vault_id, "device_id": device_id, "kind": "local-key-pepper"}


def is_available() -> bool:
    secret_module = _try_import_secret()
    if secret_module is None:
        return False
    try:
        secret_module.Service.get_sync(secret_module.ServiceFlags.NONE, None)
        return True
    except Exception:  # noqa: BLE001 - any D-Bus/service failure means unavailable
        return False


def _encode(pepper: SecretBytes) -> str:
    return base64.urlsafe_b64encode(pepper.to_bytes()).decode("ascii")


def _decode(raw: str) -> SecretBytes:
    return SecretBytes(base64.urlsafe_b64decode(raw.encode("ascii")))


def store_pepper(vault_id: str, device_id: str, pepper: SecretBytes) -> bool:
    """Best-effort store. Returns False (never raises) if no Secret
    Service is reachable -- callers fall back to FILE_ONLY tier."""
    secret_module = _try_import_secret()
    if secret_module is None:
        return False
    try:
        ok = secret_module.password_store_sync(
            _schema(secret_module),
            _attributes(vault_id, device_id),
            secret_module.COLLECTION_DEFAULT,
            f"ASH Password Manager device pepper ({device_id[:8]})",
            _encode(pepper),
            None,
        )
        return bool(ok)
    except Exception:  # noqa: BLE001
        return False


def load_pepper(vault_id: str, device_id: str) -> SecretBytes | None:
    secret_module = _try_import_secret()
    if secret_module is None:
        return None
    try:
        raw = secret_module.password_lookup_sync(_schema(secret_module), _attributes(vault_id, device_id), None)
        return _decode(raw) if raw is not None else None
    except Exception:  # noqa: BLE001
        return None


def delete_pepper(vault_id: str, device_id: str) -> bool:
    secret_module = _try_import_secret()
    if secret_module is None:
        return False
    try:
        return bool(secret_module.password_clear_sync(_schema(secret_module), _attributes(vault_id, device_id), None))
    except Exception:  # noqa: BLE001
        return False


@dataclass(frozen=True)
class PepperResult:
    pepper: SecretBytes | None
    tier: ProtectionTier


def provision_pepper(vault_id: str, device_id: str) -> PepperResult:
    """Called once at device enrollment. Tries to create and store a
    real pepper; falls back to FILE_ONLY (no pepper -- the device
    slot's KDF input is the Local Key alone) if no Secret Service is
    reachable."""
    candidate = SecretBytes(secrets.token_bytes(PEPPER_LEN))
    if store_pepper(vault_id, device_id, candidate):
        return PepperResult(pepper=candidate, tier=ProtectionTier.SECRET_SERVICE)
    candidate.wipe()
    return PepperResult(pepper=None, tier=ProtectionTier.FILE_ONLY)


def resolve_pepper(vault_id: str, device_id: str, tier: ProtectionTier) -> SecretBytes | None:
    """Called at unlock time. If the slot was created at
    SECRET_SERVICE tier but the pepper is no longer retrievable (the
    service restarted without persistence, the item was deleted
    out-of-band, etc.), this correctly returns None -- which makes
    ``unwrap_device_slot`` fail cleanly and fall back to the password,
    never silently substitute a different key."""
    if tier is ProtectionTier.FILE_ONLY:
        return None
    return load_pepper(vault_id, device_id)
