"""Tests for core.devices.registry -- device registration, Local-Key
unlock, revocation independence, and master-password change (spec
sections 5, 12, 27, 28). Uses the ``no_secret_service`` fixture
throughout since that is this project's own default-exercised tier;
see test_secret_store.py for the SECRET_SERVICE-tier path."""

from __future__ import annotations

import pytest

from passman.core.crypto import keyslots
from passman.core.crypto.kdf import Argon2Params
from passman.core.devices import local_key
from passman.core.devices.registry import (
    DeviceRevokedError,
    NoLocalKeyError,
    change_master_password,
    register_device,
    revoke_device,
    unlock_with_local_key,
    unlock_with_password,
)
from passman.core.security.memory import SecretBytes
from passman.core.vaults.layout import VaultLayout

FAST = Argon2Params(time_cost=1, memory_cost_kib=8 * 1024, parallelism=1)
VAULT_ID = "vault-1"


def _bootstrap_vault(layout: VaultLayout, vms, password: str = "master-password") -> None:
    from passman.core.devices.registry import write_devices, write_slot

    layout.ensure_dirs()
    slot = keyslots.create_password_slot(VAULT_ID, keyslots.PASSWORD_SLOT_ID, SecretBytes(password), vms, params=FAST)
    write_slot(layout, slot)
    write_devices(layout, [])


def test_unlock_with_password_round_trip(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    original = vms.to_bytes()
    _bootstrap_vault(layout, vms)
    recovered = unlock_with_password(layout, SecretBytes("master-password"))
    assert recovered.to_bytes() == original


def test_unlock_with_password_wrong_password_fails(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    _bootstrap_vault(layout, vms)
    with pytest.raises(keyslots.SlotUnwrapError):
        unlock_with_password(layout, SecretBytes("wrong-password"))


def test_register_device_creates_local_key_and_slot(fake_usb, isolated_xdg, no_secret_service):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    _bootstrap_vault(layout, vms)

    identity, local_secret = register_device(layout, VAULT_ID, vms, "Test Device")
    assert local_key.has_local_key(VAULT_ID)
    assert identity.tier == "file_only"
    assert len(local_secret.to_bytes()) == 32
    assert layout.keyslot_path(keyslots.slot_id_for_device(identity.device_id)).exists()


def test_unlock_with_local_key_matches_password_unlock(fake_usb, isolated_xdg, no_secret_service):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    original = vms.to_bytes()
    _bootstrap_vault(layout, vms)
    register_device(layout, VAULT_ID, vms, "Test Device")

    recovered = unlock_with_local_key(layout, VAULT_ID)
    assert recovered.to_bytes() == original


def test_unlock_with_local_key_with_no_enrollment_raises_no_local_key(fake_usb, isolated_xdg):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    _bootstrap_vault(layout, vms)
    with pytest.raises(NoLocalKeyError):
        unlock_with_local_key(layout, VAULT_ID)


def test_unlock_with_local_key_falls_back_cleanly_when_key_corrupt(fake_usb, isolated_xdg, no_secret_service):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    _bootstrap_vault(layout, vms)
    register_device(layout, VAULT_ID, vms, "Test Device")

    local_key.local_key_path(VAULT_ID).write_bytes(b"corrupt")
    with pytest.raises(local_key.LocalKeyError):
        unlock_with_local_key(layout, VAULT_ID)
    # Password path must still work -- no login loop (spec section 27).
    recovered = unlock_with_password(layout, SecretBytes("master-password"))
    assert recovered.to_bytes() == vms.to_bytes()


def test_two_devices_get_independent_local_keys(fake_usb, isolated_xdg, no_secret_service):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    _bootstrap_vault(layout, vms)

    identity_a, key_a = register_device(layout, VAULT_ID, vms, "Device A")
    local_key.forget_local_key(VAULT_ID)  # simulate switching to "device B" locally
    identity_b, key_b = register_device(layout, VAULT_ID, vms, "Device B")

    assert identity_a.device_id != identity_b.device_id
    assert key_a.to_bytes() != key_b.to_bytes()


def test_revoke_device_deletes_slot_and_marks_revoked(fake_usb, isolated_xdg, no_secret_service):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    _bootstrap_vault(layout, vms)
    identity, _ = register_device(layout, VAULT_ID, vms, "Test Device")

    revoke_device(layout, identity.device_id)

    assert not layout.keyslot_path(keyslots.slot_id_for_device(identity.device_id)).exists()
    with pytest.raises(DeviceRevokedError):
        unlock_with_local_key(layout, VAULT_ID)


def test_revoking_one_device_does_not_affect_another_end_to_end(fake_usb, isolated_xdg, no_secret_service):
    """The full-stack version of test_keyslots.py's pure-crypto
    revocation-independence test, through the actual registry API
    devices/vault_id namespacing included."""
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    original = vms.to_bytes()
    _bootstrap_vault(layout, vms)

    identity_a, _ = register_device(layout, VAULT_ID, vms, "Device A")
    device_a_local_dir_key = local_key.load_local_key(VAULT_ID).to_bytes()
    local_key.forget_local_key(VAULT_ID)
    identity_b, _ = register_device(layout, VAULT_ID, vms, "Device B")

    revoke_device(layout, identity_a.device_id)

    # Device B (currently "this device" locally) is unaffected.
    recovered_b = unlock_with_local_key(layout, VAULT_ID)
    assert recovered_b.to_bytes() == original

    # Device A's slot is gone even though its raw key bytes still
    # exist (proving revocation is the slot deletion, not key-file
    # possession).
    assert not layout.keyslot_path(keyslots.slot_id_for_device(identity_a.device_id)).exists()
    assert len(device_a_local_dir_key) == 32  # sanity: it really was a valid key


def test_change_master_password_updates_password_slot_only(fake_usb, isolated_xdg, no_secret_service):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    original = vms.to_bytes()
    _bootstrap_vault(layout, vms)
    register_device(layout, VAULT_ID, vms, "Test Device")

    change_master_password(layout, SecretBytes("master-password"), SecretBytes("new-master-password"), params=FAST)

    recovered_new = unlock_with_password(layout, SecretBytes("new-master-password"))
    assert recovered_new.to_bytes() == original
    with pytest.raises(keyslots.SlotUnwrapError):
        unlock_with_password(layout, SecretBytes("master-password"))

    # The already-registered device's Local Key still works unchanged.
    recovered_device = unlock_with_local_key(layout, VAULT_ID)
    assert recovered_device.to_bytes() == original


def test_list_devices_reflects_registrations_and_revocations(fake_usb, isolated_xdg, no_secret_service):
    from passman.core.devices.registry import list_devices

    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    _bootstrap_vault(layout, vms)
    identity, _ = register_device(layout, VAULT_ID, vms, "Test Device")

    devices = list_devices(layout)
    assert len(devices) == 1
    assert devices[0].label == "Test Device"
    assert not devices[0].is_revoked

    revoke_device(layout, identity.device_id)
    devices = list_devices(layout)
    assert devices[0].is_revoked
