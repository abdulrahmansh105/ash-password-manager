"""Per-device Local Key storage (spec sections 4, 28).

The Local Key itself is nothing more than 32 random bytes living in a
0600 file named exactly ``ash-pass-manager.key``. What makes it
*device-bound* is not the file -- it's that unwrapping a vault's
``device-<id>.slot`` also requires this device's current
``core.crypto.binding.compute_binding()`` value to match what the slot
was created with (see ``core.crypto.keyslots``). Copying this file to
another machine copies 32 useless random bytes; the slot on the USB
still will not open there, and login cleanly falls back to the master
password (spec section 27).

Storage lives under ``XDG_DATA_HOME``, never inside the project tree
and never on the USB -- see ``core.devices.registry`` for the on-USB
counterpart (the device *slot*, and the ``devices.json`` roster).
"""

from __future__ import annotations

import json
import os
import secrets
import time
import uuid as uuid_mod
from dataclasses import asdict, dataclass
from pathlib import Path

from ..appdirs import data_home
from ..security.memory import SecretBytes
from ..util.atomic_json import ensure_dir, write_json_atomic

LOCAL_KEY_FILENAME = "ash-pass-manager.key"
LOCAL_KEY_LEN = 32
FILE_MODE = 0o600


def device_dir(vault_id: str) -> Path:
    return data_home() / "devices" / vault_id


class LocalKeyError(Exception):
    """Missing, corrupt, or unreadable Local Key material. Never
    carries key bytes."""


@dataclass
class DeviceIdentity:
    device_id: str
    vault_id: str
    label: str
    created_utc: str
    tier: str  # "secret_service" | "file_only" -- see secret_store.py


def generate_device_id() -> str:
    # Random, not machine-derived: the USB must carry no machine
    # fingerprint (spec section 4). A UUID4 is convenient,
    # fixed-length, and collision-safe for this purpose.
    return uuid_mod.uuid4().hex


def local_key_path(vault_id: str) -> Path:
    return device_dir(vault_id) / LOCAL_KEY_FILENAME


def identity_path(vault_id: str) -> Path:
    return device_dir(vault_id) / "device.json"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def generate_local_key(vault_id: str, device_id: str, label: str, tier: str) -> SecretBytes:
    """Create and persist a brand-new Local Key for this (vault,
    device) pair. Refuses to silently overwrite an existing key --
    callers that want to re-enroll must call ``replace_local_key``, so
    a bug can never quietly orphan a working key and lock a valid slot
    out from under the user."""
    key_dir = device_dir(vault_id)
    ensure_dir(key_dir)
    key_path = local_key_path(vault_id)
    if key_path.exists():
        raise LocalKeyError(f"A Local Key already exists for this vault on this device: {key_path}")
    raw = secrets.token_bytes(LOCAL_KEY_LEN)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    _write_identity(
        vault_id,
        DeviceIdentity(device_id=device_id, vault_id=vault_id, label=label, created_utc=_now(), tier=tier),
    )
    return SecretBytes(raw)


def replace_local_key(vault_id: str, device_id: str, label: str, tier: str) -> SecretBytes:
    """Used only for re-enrollment on this same device (e.g. a
    corrupted key). Removes any existing key/identity first."""
    forget_local_key(vault_id)
    return generate_local_key(vault_id, device_id, label, tier)


def load_local_key(vault_id: str) -> SecretBytes:
    path = local_key_path(vault_id)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LocalKeyError(f"Local Key not found or unreadable: {type(exc).__name__}") from exc
    if len(raw) != LOCAL_KEY_LEN:
        raise LocalKeyError("Local Key file is corrupt (unexpected size).")
    return SecretBytes(raw)


def load_identity(vault_id: str) -> DeviceIdentity | None:
    try:
        raw = json.loads(identity_path(vault_id).read_text(encoding="utf-8"))
        return DeviceIdentity(**{k: raw[k] for k in DeviceIdentity.__dataclass_fields__})
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None


def _write_identity(vault_id: str, identity: DeviceIdentity) -> None:
    write_json_atomic(identity_path(vault_id), asdict(identity), mode=FILE_MODE)


def has_local_key(vault_id: str) -> bool:
    return local_key_path(vault_id).exists()


def forget_local_key(vault_id: str) -> None:
    """Remove this device's Local Key + identity for one vault (used
    for revocation acknowledgement and re-enrollment). Never touches
    the USB -- the matching ``device-<id>.slot`` there is a separate,
    explicit deletion (see ``core.devices.registry.revoke_device``)."""
    for path in (local_key_path(vault_id), identity_path(vault_id)):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
