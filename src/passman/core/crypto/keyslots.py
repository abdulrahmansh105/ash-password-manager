"""Key-slot format: LUKS-style wrapping of the Vault Master Secret
(VMS) under independent credentials (spec sections 4, 5, 12, 28).

Each slot is a small, independent, self-describing record. Losing or
deleting one slot can never affect another, because they share no key
material -- only the plaintext VMS they each separately protect, which
none of them ever store. This is what makes device revocation and
password changes both cheap and safe:

  * Revoke a device -> delete its ``device-<id>.slot``. Every other
    slot is untouched and keeps unwrapping VMS exactly as before.
  * Change the master password -> rewrap ``password.slot`` only
    (``rewrap_password_slot``). VMS itself never changes, so every
    registered device's slot keeps working with zero changes.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..security.memory import SecretBytes
from .aead import AeadError, SealedBox, open_box, seal
from .binding import DEFAULT_BINDING_INPUTS, BindingInput, compute_binding
from .kdf import Argon2Params, derive_key_argon2id, hkdf_sha256

VMS_LEN = 32
SLOT_FORMAT_VERSION = 1
SALT_LEN = 16
PASSWORD_SLOT_ID = "password"


class KeySlotError(Exception):
    """Base class. Messages never contain key material."""


class SlotUnwrapError(KeySlotError):
    """Wrong credential, tampered slot, or a mismatched device binding
    -- deliberately indistinguishable from each other in the message
    text (spec section 21: never leak whether a secret was "close")."""


class SlotFormatError(KeySlotError):
    """The slot file/dict is missing fields, malformed, or has an
    unrecognized format version."""


class SlotKind(str, Enum):
    PASSWORD = "password"
    DEVICE = "device"


def slot_id_for_device(device_id: str) -> str:
    return f"device-{device_id}"


def generate_vms() -> SecretBytes:
    return SecretBytes(secrets.token_bytes(VMS_LEN))


def vms_to_kdbx_password(vms: SecretBytes) -> str:
    """The one, shared encoding of the Vault Master Secret into the
    KDBX file's actual password string (base64url of the 256-bit VMS
    -- a fixed-length ASCII encoding, not a second secret; the actual
    guessing barrier is the Argon2id password slot that wraps this
    VMS, not the KDBX file's own KDF -- see docs/SECURITY.md). Used by
    both vault creation/adoption (``core.vault.provisioning``) and
    every login path (``ui.login``), so there is exactly one place
    this representation is defined."""
    return base64.urlsafe_b64encode(vms.to_bytes()).decode("ascii")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _aad(vault_id: str, slot_id: str, kind: SlotKind) -> bytes:
    return f"ash-pm/slot/v{SLOT_FORMAT_VERSION}/{vault_id}/{slot_id}/{kind.value}".encode()


def _zero(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


@dataclass
class KeySlot:
    """One wrapped copy of the Vault Master Secret."""

    slot_id: str
    kind: SlotKind
    vault_id: str
    salt: bytes
    box: SealedBox
    created_utc: str
    version: int = SLOT_FORMAT_VERSION
    label: str = ""
    # PASSWORD slots only:
    argon2_params: Argon2Params | None = None
    # DEVICE slots only:
    device_id: str | None = None
    binding_inputs: tuple[BindingInput, ...] = DEFAULT_BINDING_INPUTS

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "version": self.version,
            "slot_id": self.slot_id,
            "kind": self.kind.value,
            "vault_id": self.vault_id,
            "salt": _b64(self.salt),
            "nonce": _b64(self.box.nonce),
            "ciphertext": _b64(self.box.ciphertext),
            "tag": _b64(self.box.tag),
            "created_utc": self.created_utc,
            "label": self.label,
        }
        if self.kind is SlotKind.PASSWORD:
            d["argon2"] = (self.argon2_params or Argon2Params()).to_dict()
        else:
            d["device_id"] = self.device_id
            d["binding_inputs"] = [i.value for i in self.binding_inputs]
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> KeySlot:
        try:
            version = int(d["version"])
            if version != SLOT_FORMAT_VERSION:
                raise SlotFormatError(f"Unsupported key-slot format version: {version}")
            kind = SlotKind(d["kind"])
            box = SealedBox(nonce=_unb64(d["nonce"]), ciphertext=_unb64(d["ciphertext"]), tag=_unb64(d["tag"]))
            slot = KeySlot(
                slot_id=str(d["slot_id"]),
                kind=kind,
                vault_id=str(d["vault_id"]),
                salt=_unb64(d["salt"]),
                box=box,
                created_utc=str(d.get("created_utc", "")),
                version=version,
                label=str(d.get("label", "")),
            )
            if kind is SlotKind.PASSWORD:
                argon2_raw = d.get("argon2")
                slot.argon2_params = Argon2Params.from_dict(argon2_raw) if argon2_raw else Argon2Params()
            else:
                slot.device_id = str(d["device_id"])
                slot.binding_inputs = tuple(
                    BindingInput(v) for v in d.get("binding_inputs", [i.value for i in DEFAULT_BINDING_INPUTS])
                )
            return slot
        except SlotFormatError:
            raise
        except (KeyError, ValueError, TypeError) as exc:
            raise SlotFormatError(f"Malformed key slot: {type(exc).__name__}") from exc


def create_password_slot(
    vault_id: str,
    slot_id: str,
    password: SecretBytes,
    vms: SecretBytes,
    *,
    params: Argon2Params | None = None,
    created_utc: str = "",
    label: str = "Master password",
) -> KeySlot:
    params = params or Argon2Params()
    salt = secrets.token_bytes(SALT_LEN)
    kek = bytearray(derive_key_argon2id(password, salt, params))
    try:
        box = seal(bytes(kek), vms.to_bytes(), aad=_aad(vault_id, slot_id, SlotKind.PASSWORD))
    finally:
        _zero(kek)
    return KeySlot(
        slot_id=slot_id,
        kind=SlotKind.PASSWORD,
        vault_id=vault_id,
        salt=salt,
        box=box,
        created_utc=created_utc or _now(),
        argon2_params=params,
        label=label,
    )


def unwrap_password_slot(slot: KeySlot, password: SecretBytes) -> SecretBytes:
    """Caller retains ownership of ``password`` -- this never wipes it,
    since some callers (e.g. a master-password change) need to reuse
    the same credential right after for a second operation."""
    if slot.kind is not SlotKind.PASSWORD:
        raise SlotFormatError("Not a password slot.")
    params = slot.argon2_params or Argon2Params()
    kek = bytearray(derive_key_argon2id(password, slot.salt, params))
    try:
        plaintext = open_box(bytes(kek), slot.box, aad=_aad(slot.vault_id, slot.slot_id, SlotKind.PASSWORD))
    except AeadError as exc:
        raise SlotUnwrapError("Incorrect password.") from exc
    finally:
        _zero(kek)
    return SecretBytes(plaintext)


def _device_ikm(local_key: SecretBytes, pepper: SecretBytes | None) -> bytes:
    return local_key.to_bytes() + (pepper.to_bytes() if pepper is not None else b"")


def create_device_slot(
    vault_id: str,
    slot_id: str,
    device_id: str,
    local_key: SecretBytes,
    pepper: SecretBytes | None,
    vms: SecretBytes,
    *,
    binding_inputs: tuple[BindingInput, ...] = DEFAULT_BINDING_INPUTS,
    created_utc: str = "",
    label: str = "",
) -> KeySlot:
    salt = secrets.token_bytes(SALT_LEN)
    binding = compute_binding(binding_inputs)
    info = _aad(vault_id, slot_id, SlotKind.DEVICE) + b"|" + device_id.encode("utf-8") + b"|" + binding
    kek = bytearray(hkdf_sha256(_device_ikm(local_key, pepper), salt, info))
    try:
        box = seal(bytes(kek), vms.to_bytes(), aad=_aad(vault_id, slot_id, SlotKind.DEVICE))
    finally:
        _zero(kek)
    return KeySlot(
        slot_id=slot_id,
        kind=SlotKind.DEVICE,
        vault_id=vault_id,
        salt=salt,
        box=box,
        created_utc=created_utc or _now(),
        device_id=device_id,
        binding_inputs=binding_inputs,
        label=label,
    )


def unwrap_device_slot(slot: KeySlot, local_key: SecretBytes, pepper: SecretBytes | None) -> SecretBytes:
    if slot.kind is not SlotKind.DEVICE:
        raise SlotFormatError("Not a device slot.")
    binding = compute_binding(slot.binding_inputs)
    info = (
        _aad(slot.vault_id, slot.slot_id, SlotKind.DEVICE)
        + b"|"
        + (slot.device_id or "").encode("utf-8")
        + b"|"
        + binding
    )
    kek = bytearray(hkdf_sha256(_device_ikm(local_key, pepper), slot.salt, info))
    try:
        plaintext = open_box(bytes(kek), slot.box, aad=_aad(slot.vault_id, slot.slot_id, SlotKind.DEVICE))
    except AeadError as exc:
        raise SlotUnwrapError("Local Key is invalid for this device.") from exc
    finally:
        _zero(kek)
    return SecretBytes(plaintext)


def rewrap_password_slot(
    old_slot: KeySlot,
    old_password: SecretBytes,
    new_password: SecretBytes,
    *,
    params: Argon2Params | None = None,
) -> KeySlot:
    """Change the master password: unwrap VMS with the old password,
    rewrap with the new one. Every device slot is untouched -- VMS
    itself never changes. Neither ``old_password`` nor ``new_password``
    is wiped here; the caller owns their lifetime."""
    vms = unwrap_password_slot(old_slot, old_password)
    try:
        return create_password_slot(
            old_slot.vault_id,
            old_slot.slot_id,
            new_password,
            vms,
            params=params or old_slot.argon2_params,
            created_utc=old_slot.created_utc,
            label=old_slot.label,
        )
    finally:
        vms.wipe()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
