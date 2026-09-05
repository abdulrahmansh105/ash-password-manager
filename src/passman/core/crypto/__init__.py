"""Vault credential cryptography: KDFs, AEAD sealing, device binding,
and the key-slot format built from them.

This package implements the design documented in ``docs/SECURITY.md``:
a random 256-bit Vault Master Secret (VMS) is the KDBX file's actual
password, and it is never stored in the clear -- only wrapped copies
("key slots") exist, one per credential (the master password, and one
per registered device's Local Key). No custom cryptography is
invented here: Argon2id (``argon2-cffi``) for password-based key
derivation, HKDF-SHA256 (stdlib ``hmac``/``hashlib``) for combining an
already-random Local Key with an optional secret-store pepper, and
AES-256-GCM (``pycryptodomex``) for authenticated encryption -- the
standard key-wrapping/key-slot pattern LUKS itself uses, applied to a
single small secret instead of a disk.
"""

from __future__ import annotations

from .aead import AeadError, SealedBox, open_box, seal
from .binding import BindingInput, DEFAULT_BINDING_INPUTS, compute_binding
from .kdf import Argon2Params, derive_key_argon2id, hkdf_sha256
from .keyslots import (
    KeySlot,
    KeySlotError,
    PASSWORD_SLOT_ID,
    SlotFormatError,
    SlotKind,
    SlotUnwrapError,
    create_device_slot,
    create_password_slot,
    generate_vms,
    rewrap_password_slot,
    slot_id_for_device,
    unwrap_device_slot,
    unwrap_password_slot,
    vms_to_kdbx_password,
)

__all__ = [
    "AeadError",
    "SealedBox",
    "seal",
    "open_box",
    "BindingInput",
    "DEFAULT_BINDING_INPUTS",
    "compute_binding",
    "Argon2Params",
    "derive_key_argon2id",
    "hkdf_sha256",
    "KeySlot",
    "KeySlotError",
    "SlotFormatError",
    "SlotUnwrapError",
    "SlotKind",
    "PASSWORD_SLOT_ID",
    "generate_vms",
    "create_password_slot",
    "unwrap_password_slot",
    "create_device_slot",
    "unwrap_device_slot",
    "rewrap_password_slot",
    "slot_id_for_device",
    "vms_to_kdbx_password",
]
