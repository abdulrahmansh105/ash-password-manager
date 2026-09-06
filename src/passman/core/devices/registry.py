"""On-USB device registry: ``devices.json`` + the key-slot files under
``keyslots/`` (spec sections 5, 12, 27, 28).

This is the layer that turns the primitives in ``core.crypto`` and
``core.devices.local_key``/``secret_store`` into actual product
operations: register a new device, unlock with a Local Key, unlock
with the master password, change the master password, and revoke a
device. Every function here operates on one vault's ``VaultLayout``
and has no GTK/UI dependency.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass

from ..crypto import keyslots
from ..crypto.keyslots import (  # noqa: F401 - re-exported for callers
    KeySlot,
    SlotUnwrapError,
)
from ..security.memory import SecretBytes
from ..util.atomic_json import read_json, write_json_atomic
from ..vaults import health
from ..vaults.layout import VaultLayout
from . import local_key, secret_store
from .secret_store import ProtectionTier

__all__ = [
    "DeviceRecord",
    "DeviceRegistryError",
    "DeviceRevokedError",
    "NoLocalKeyError",
    "VaultUnreadableError",
    "change_master_password",
    "list_devices",
    "read_devices",
    "read_slot",
    "register_device",
    "revoke_device",
    "unlock_with_local_key",
    "unlock_with_password",
    "write_devices",
    "write_slot",
]


class DeviceRegistryError(Exception):
    pass


class DeviceRevokedError(DeviceRegistryError):
    pass


class NoLocalKeyError(DeviceRegistryError):
    """No Local Key is enrolled for this device on this vault -- a
    normal, expected state (spec section 27: falls through to the
    password), not a corruption."""


class VaultUnreadableError(DeviceRegistryError):
    """The key slot exists on disk but could not even be read (e.g. a
    permission error, or the vault's own container directory owned by
    a different OS user than the one currently logging in -- confirmed
    live: a portable USB vault set up under one Linux account and then
    used from another is unreadable by that second account entirely).

    Deliberately distinct from a plain ``DeviceRegistryError`` ("no
    such slot", a legitimate "not enrolled" state) and from
    ``core.crypto.keyslots.SlotUnwrapError`` (an actual wrong
    password) -- callers must never fold this into "Incorrect
    password": the password was never even compared."""


@dataclass
class DeviceRecord:
    device_id: str
    label: str
    tier: str
    registered_utc: str
    last_seen_utc: str | None = None
    revoked_utc: str | None = None
    os_release: str = ""

    @property
    def is_revoked(self) -> bool:
        return self.revoked_utc is not None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_devices(layout: VaultLayout) -> list[DeviceRecord]:
    raw = read_json(layout.devices_json, [])
    records = []
    for item in raw if isinstance(raw, list) else []:
        try:
            records.append(DeviceRecord(**{k: item[k] for k in DeviceRecord.__dataclass_fields__ if k in item}))
        except (KeyError, TypeError):
            continue
    return records


def write_devices(layout: VaultLayout, records: list[DeviceRecord]) -> None:
    layout.ensure_dirs()
    write_json_atomic(layout.devices_json, [asdict(r) for r in records])
    health.update_integrity_manifest(layout)


def list_devices(layout: VaultLayout) -> list[DeviceRecord]:
    return read_devices(layout)


def read_slot(layout: VaultLayout, slot_id: str) -> KeySlot:
    """Deliberately does not go through ``util.atomic_json.read_json``
    -- that helper folds a missing file and an unreadable one (wrong
    permissions, a stale mount, an I/O error) into the same "use the
    default" outcome, which is the right call for a settings file that
    may legitimately not exist yet, but wrong here: a key slot that
    exists but can't be read must never look like "not enrolled",
    because every caller (in particular ``unlock_with_password``)
    otherwise cannot be told apart from an actual wrong password."""
    path = layout.keyslot_path(slot_id)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DeviceRegistryError(f"Key slot not found: {slot_id}") from None
    except OSError as exc:
        raise VaultUnreadableError(f"Key slot {slot_id!r} exists but could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise DeviceRegistryError(f"Key slot {slot_id!r} is corrupt: {exc}") from exc
    return KeySlot.from_dict(raw)


def write_slot(layout: VaultLayout, slot: KeySlot) -> None:
    layout.ensure_dirs()
    write_json_atomic(layout.keyslot_path(slot.slot_id), slot.to_dict())
    health.update_integrity_manifest(layout)


def unlock_with_password(layout: VaultLayout, password: SecretBytes) -> SecretBytes:
    """Spec section 27's ASK_PASSWORD -> OPEN_VAULT path. Raises
    ``SlotUnwrapError`` (incorrect password), ``DeviceRegistryError``
    (missing/corrupt password slot -- a broken vault, not a wrong
    credential), or ``VaultUnreadableError`` (the slot file exists but
    couldn't even be opened -- e.g. a permission problem -- so the
    password was never actually compared) -- callers must distinguish
    all of these for error messaging but never for timing (spec
    section 21)."""
    slot = read_slot(layout, keyslots.PASSWORD_SLOT_ID)
    return keyslots.unwrap_password_slot(slot, password)


def register_device(
    layout: VaultLayout,
    vault_id: str,
    vms: SecretBytes,
    label: str,
    *,
    os_release: str = "",
) -> tuple[local_key.DeviceIdentity, SecretBytes]:
    """Mint a brand-new device_id + Local Key + device slot for this
    vault, on this device. Never reuses or copies key material from
    any other device (spec section 5)."""
    device_id = local_key.generate_device_id()
    pepper_result = secret_store.provision_pepper(vault_id, device_id)
    local_secret = local_key.generate_local_key(vault_id, device_id, label, pepper_result.tier.value)
    try:
        slot = keyslots.create_device_slot(
            vault_id,
            keyslots.slot_id_for_device(device_id),
            device_id,
            local_secret,
            pepper_result.pepper,
            vms,
            created_utc=_now(),
            label=label,
        )
        write_slot(layout, slot)
    finally:
        if pepper_result.pepper is not None:
            pepper_result.pepper.wipe()

    records = read_devices(layout)
    records.append(
        DeviceRecord(
            device_id=device_id,
            label=label,
            tier=pepper_result.tier.value,
            registered_utc=_now(),
            last_seen_utc=_now(),
            os_release=os_release,
        )
    )
    write_devices(layout, records)
    identity = local_key.load_identity(vault_id)
    return identity, local_secret


def unlock_with_local_key(layout: VaultLayout, vault_id: str) -> SecretBytes:
    """Spec section 27's CHECK_LOCAL_KEY -> UNLOCK_WITH_LOCAL_KEY path.
    Raises ``NoLocalKeyError``, ``DeviceRevokedError``, or
    ``SlotUnwrapError`` for every distinct failure the login state
    machine needs to fall back to the password on -- never returns a
    partially-valid result."""
    if not local_key.has_local_key(vault_id):
        raise NoLocalKeyError("No Local Key enrolled for this device.")
    identity = local_key.load_identity(vault_id)
    if identity is None:
        raise NoLocalKeyError("Local Key identity metadata is missing or corrupt.")

    records = {r.device_id: r for r in read_devices(layout)}
    record = records.get(identity.device_id)
    if record is not None and record.is_revoked:
        raise DeviceRevokedError("This device has been revoked for this vault.")

    local_secret = local_key.load_local_key(vault_id)
    tier = ProtectionTier(identity.tier) if identity.tier in {t.value for t in ProtectionTier} else ProtectionTier.FILE_ONLY
    pepper = secret_store.resolve_pepper(vault_id, identity.device_id, tier)
    try:
        try:
            slot = read_slot(layout, keyslots.slot_id_for_device(identity.device_id))
        except DeviceRegistryError as exc:
            raise NoLocalKeyError(f"No matching device slot on this vault: {exc}") from exc
        vms = keyslots.unwrap_device_slot(slot, local_secret, pepper)
    finally:
        local_secret.wipe()
        if pepper is not None:
            pepper.wipe()

    if record is not None:
        record.last_seen_utc = _now()
        write_devices(layout, list(records.values()))
    return vms


def revoke_device(layout: VaultLayout, device_id: str) -> None:
    """Deletes the device's key slot outright -- the real
    cryptographic revocation: that device can no longer derive VMS
    even with its key file intact -- and marks the ``devices.json``
    record revoked so it stays visible in Settings -> Devices. Every
    other device's slot is untouched, because slots share no key
    material (spec section 12)."""
    try:
        layout.keyslot_path(keyslots.slot_id_for_device(device_id)).unlink()
    except FileNotFoundError:
        pass
    records = read_devices(layout)
    for r in records:
        if r.device_id == device_id and not r.is_revoked:
            r.revoked_utc = _now()
    write_devices(layout, records)
    health.update_integrity_manifest(layout)


def reset_master_password_with_local_key(
    layout: VaultLayout,
    vault_id: str,
    new_password: SecretBytes,
    *,
    params=None,
) -> None:
    """Replace the master-password slot after authenticating with the
    device's Local Key. The VMS never changes: authentication happens by
    unwrapping the existing device slot, then only ``password.slot`` is
    regenerated. This is the intentional password-forgotten path when a
    valid Local Key is available on this device."""
    vms = unlock_with_local_key(layout, vault_id)
    try:
        new_slot = keyslots.create_password_slot(
            vault_id,
            keyslots.PASSWORD_SLOT_ID,
            new_password,
            vms,
            params=params,
        )
        write_slot(layout, new_slot)
    finally:
        vms.wipe()


def change_master_password(
    layout: VaultLayout,
    old_password: SecretBytes,
    new_password: SecretBytes,
    *,
    params=None,
) -> None:
    """Rewraps ONLY ``password.slot``. VMS itself is unchanged, so
    every registered device's slot keeps working with no changes at
    all -- the required "password change is cheap and doesn't break
    other devices" property (spec sections 4, 12)."""
    old_slot = read_slot(layout, keyslots.PASSWORD_SLOT_ID)
    new_slot = keyslots.rewrap_password_slot(old_slot, old_password, new_password, params=params)
    write_slot(layout, new_slot)
