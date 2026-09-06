"""Device identity, Local Key storage, secret-store peppering, and the
on-USB device registry (spec sections 4, 5, 12, 28)."""

from __future__ import annotations

from . import local_key, secret_store
from .registry import (
    DeviceRecord,
    DeviceRegistryError,
    DeviceRevokedError,
    NoLocalKeyError,
    change_master_password,
    list_devices,
    read_devices,
    read_slot,
    register_device,
    revoke_device,
    reset_master_password_with_local_key,
    unlock_with_local_key,
    unlock_with_password,
    write_devices,
    write_slot,
)

__all__ = [
    "DeviceRecord",
    "DeviceRegistryError",
    "DeviceRevokedError",
    "NoLocalKeyError",
    "change_master_password",
    "list_devices",
    "local_key",
    "read_devices",
    "read_slot",
    "register_device",
    "revoke_device",
    "reset_master_password_with_local_key",
    "secret_store",
    "unlock_with_local_key",
    "unlock_with_password",
    "write_devices",
    "write_slot",
]
