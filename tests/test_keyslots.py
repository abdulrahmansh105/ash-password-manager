"""Security-critical tests for core.crypto.keyslots -- the actual
credential model of the whole product (spec sections 4, 5, 12, 28)."""

from __future__ import annotations

import dataclasses

import pytest

from passman.core.crypto.binding import BindingInput
from passman.core.crypto.kdf import Argon2Params
from passman.core.crypto.keyslots import (
    KeySlot,
    SlotFormatError,
    SlotUnwrapError,
    create_device_slot,
    create_password_slot,
    generate_vms,
    rewrap_password_slot,
    slot_id_for_device,
    unwrap_device_slot,
    unwrap_password_slot,
)
from passman.core.security.memory import SecretBytes

FAST = Argon2Params(time_cost=1, memory_cost_kib=8 * 1024, parallelism=1)
VAULT_ID = "vault-1"


def test_password_slot_round_trip():
    vms = generate_vms()
    original = vms.to_bytes()
    slot = create_password_slot(VAULT_ID, "password", SecretBytes("correct-password"), vms, params=FAST)
    recovered = unwrap_password_slot(slot, SecretBytes("correct-password"))
    assert recovered.to_bytes() == original


def test_password_slot_rejects_wrong_password():
    vms = generate_vms()
    slot = create_password_slot(VAULT_ID, "password", SecretBytes("correct-password"), vms, params=FAST)
    with pytest.raises(SlotUnwrapError):
        unwrap_password_slot(slot, SecretBytes("wrong-password"))


def test_password_slot_serialization_round_trip():
    vms = generate_vms()
    slot = create_password_slot(VAULT_ID, "password", SecretBytes("hunter2"), vms, params=FAST)
    restored = KeySlot.from_dict(slot.to_dict())
    recovered = unwrap_password_slot(restored, SecretBytes("hunter2"))
    assert recovered.to_bytes() == vms.to_bytes()


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "tag"])
def test_password_slot_rejects_tampered_box_field(field):
    vms = generate_vms()
    slot = create_password_slot(VAULT_ID, "password", SecretBytes("hunter2"), vms, params=FAST)
    original = getattr(slot.box, field)
    tampered_value = bytes([original[0] ^ 1]) + original[1:]
    tampered_box = dataclasses.replace(slot.box, **{field: tampered_value})
    tampered_slot = dataclasses.replace(slot, box=tampered_box)
    with pytest.raises(SlotUnwrapError):
        unwrap_password_slot(tampered_slot, SecretBytes("hunter2"))


def test_password_slot_rejects_tampered_salt():
    vms = generate_vms()
    slot = create_password_slot(VAULT_ID, "password", SecretBytes("hunter2"), vms, params=FAST)
    tampered = dataclasses.replace(slot, salt=bytes([slot.salt[0] ^ 1]) + slot.salt[1:])
    with pytest.raises(SlotUnwrapError):
        unwrap_password_slot(tampered, SecretBytes("hunter2"))


def test_password_slot_rejects_tampered_aad_via_relabeled_vault_id():
    """AAD is derived from (vault_id, slot_id, kind) at unwrap time,
    not stored separately -- "tampering AAD" means the slot was moved
    or relabeled to a different vault_id than it was created under."""
    vms = generate_vms()
    slot = create_password_slot(VAULT_ID, "password", SecretBytes("hunter2"), vms, params=FAST)
    relabeled = dataclasses.replace(slot, vault_id="different-vault")
    with pytest.raises(SlotUnwrapError):
        unwrap_password_slot(relabeled, SecretBytes("hunter2"))


def test_device_slot_round_trip_no_pepper():
    vms = generate_vms()
    slot = create_device_slot(VAULT_ID, slot_id_for_device("abc"), "abc", SecretBytes(b"L" * 32), None, vms)
    recovered = unwrap_device_slot(slot, SecretBytes(b"L" * 32), None)
    assert recovered.to_bytes() == vms.to_bytes()


def test_device_slot_round_trip_with_pepper():
    vms = generate_vms()
    slot = create_device_slot(
        VAULT_ID, slot_id_for_device("abc"), "abc", SecretBytes(b"L" * 32), SecretBytes(b"P" * 32), vms
    )
    recovered = unwrap_device_slot(slot, SecretBytes(b"L" * 32), SecretBytes(b"P" * 32))
    assert recovered.to_bytes() == vms.to_bytes()


def test_device_slot_requires_matching_pepper():
    vms = generate_vms()
    slot = create_device_slot(
        VAULT_ID, slot_id_for_device("abc"), "abc", SecretBytes(b"L" * 32), SecretBytes(b"P" * 32), vms
    )
    with pytest.raises(SlotUnwrapError):
        unwrap_device_slot(slot, SecretBytes(b"L" * 32), None)  # pepper now missing


def test_device_slot_rejects_copied_key_file_under_different_binding(monkeypatch):
    """The core anti-portability property (spec section 28): the exact
    same Local Key bytes, wrapped under one device's binding, must not
    unwrap once the binding changes -- this is what stops "copy the
    key file to another machine" from working."""
    vms = generate_vms()
    local_key_bytes = b"L" * 32
    monkeypatch.setattr("os.getuid", lambda: 1111)
    slot = create_device_slot(
        VAULT_ID,
        slot_id_for_device("abc"),
        "abc",
        SecretBytes(local_key_bytes),
        None,
        vms,
        binding_inputs=(BindingInput.UID,),
    )

    # Simulate "the key file was copied to a different device": same
    # key bytes, but the binding-relevant environment now differs.
    monkeypatch.setattr("os.getuid", lambda: 2222)
    with pytest.raises(SlotUnwrapError):
        unwrap_device_slot(slot, SecretBytes(local_key_bytes), None)


def test_device_slot_binding_inputs_are_preserved_through_serialization():
    vms = generate_vms()
    slot = create_device_slot(
        VAULT_ID,
        slot_id_for_device("abc"),
        "abc",
        SecretBytes(b"L" * 32),
        None,
        vms,
        binding_inputs=(BindingInput.UID, BindingInput.USERNAME),
    )
    restored = KeySlot.from_dict(slot.to_dict())
    assert restored.binding_inputs == (BindingInput.UID, BindingInput.USERNAME)
    recovered = unwrap_device_slot(restored, SecretBytes(b"L" * 32), None)
    assert recovered.to_bytes() == vms.to_bytes()


def test_revoking_one_device_does_not_affect_another():
    """spec section 12: deleting one device's slot must not affect any
    other device's ability to unlock -- they share no key material."""
    vms = generate_vms()
    original = vms.to_bytes()
    slot_a = create_device_slot(VAULT_ID, slot_id_for_device("a"), "a", SecretBytes(b"A" * 32), None, vms)
    slot_b = create_device_slot(VAULT_ID, slot_id_for_device("b"), "b", SecretBytes(b"B" * 32), None, vms)

    del slot_a  # "revoke" device A by discarding its slot entirely

    recovered_b = unwrap_device_slot(slot_b, SecretBytes(b"B" * 32), None)
    assert recovered_b.to_bytes() == original


def test_password_change_does_not_affect_device_slots():
    """spec sections 4/12: changing the master password rewraps only
    the password slot; VMS is unchanged so every device slot keeps
    working with zero changes."""
    vms = generate_vms()
    original = vms.to_bytes()
    password_slot = create_password_slot(VAULT_ID, "password", SecretBytes("old-password"), vms, params=FAST)
    device_slot = create_device_slot(VAULT_ID, slot_id_for_device("a"), "a", SecretBytes(b"A" * 32), None, vms)

    new_slot = rewrap_password_slot(
        password_slot, SecretBytes("old-password"), SecretBytes("new-password"), params=FAST
    )

    assert unwrap_password_slot(new_slot, SecretBytes("new-password")).to_bytes() == original
    with pytest.raises(SlotUnwrapError):
        unwrap_password_slot(new_slot, SecretBytes("old-password"))
    assert unwrap_device_slot(device_slot, SecretBytes(b"A" * 32), None).to_bytes() == original


def test_unsupported_slot_version_is_rejected():
    vms = generate_vms()
    slot = create_password_slot(VAULT_ID, "password", SecretBytes("x"), vms, params=FAST)
    raw = slot.to_dict()
    raw["version"] = 999
    with pytest.raises(SlotFormatError):
        KeySlot.from_dict(raw)


def test_malformed_slot_dict_is_rejected():
    with pytest.raises(SlotFormatError):
        KeySlot.from_dict({"version": 1, "kind": "password"})  # missing required fields


def test_slot_id_for_device_is_prefixed():
    assert slot_id_for_device("abc123") == "device-abc123"
