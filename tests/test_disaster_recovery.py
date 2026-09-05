"""End-to-end disaster-recovery invariant: a Local Key must never be
able to make a vault unrecoverable. Simulates an OS reinstall / disk
replacement -- local device-key storage wiped, every device-binding
input changed -- and asserts the master password still opens the
vault, a fresh Local Key enrolls successfully, and the orphaned device
slot stays visible for revocation without disturbing the new one."""

from __future__ import annotations

import shutil

import pytest

from passman.core.crypto import keyslots
from passman.core.crypto.kdf import Argon2Params
from passman.core.devices import local_key
from passman.core.devices.registry import (
    list_devices,
    register_device,
    revoke_device,
    unlock_with_local_key,
    unlock_with_password,
    write_devices,
    write_slot,
)
from passman.core.security.memory import SecretBytes
from passman.core.vaults.layout import VaultLayout

FAST = Argon2Params(time_cost=1, memory_cost_kib=8 * 1024, parallelism=1)
VAULT_ID = "vault-1"


def _bootstrap_vault(layout: VaultLayout, vms, password: str = "master-password") -> None:
    layout.ensure_dirs()
    slot = keyslots.create_password_slot(VAULT_ID, keyslots.PASSWORD_SLOT_ID, SecretBytes(password), vms, params=FAST)
    write_slot(layout, slot)
    write_devices(layout, [])


def test_disk_replacement_never_bricks_the_vault(fake_usb, isolated_xdg, no_secret_service, monkeypatch):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    original = vms.to_bytes()
    _bootstrap_vault(layout, vms)

    old_identity, _ = register_device(layout, VAULT_ID, vms, "Old Laptop")
    assert unlock_with_local_key(layout, VAULT_ID).to_bytes() == original  # sanity, pre-"disaster"

    # --- Simulate a full OS reinstall / disk replacement ---
    shutil.rmtree(local_key.data_home(), ignore_errors=True)  # wipes ~/.local/share/ash-password-manager
    monkeypatch.setattr("os.getuid", lambda: 999999)  # the UID binding component now differs
    monkeypatch.setattr("passman.core.crypto.binding._MACHINE_ID_PATHS", ())  # machine-id regenerated/gone

    # The old device's Local Key is gone along with the wiped local storage.
    with pytest.raises(local_key.LocalKeyError):
        local_key.load_local_key(VAULT_ID)

    # The master password must still work -- it never depended on any
    # device-local state at all (spec: "The Local Key can never make a
    # vault unrecoverable").
    recovered = unlock_with_password(layout, SecretBytes("master-password"))
    assert recovered.to_bytes() == original

    # A new device enrolls cleanly after re-authenticating by password.
    new_identity, _new_secret = register_device(layout, VAULT_ID, vms, "Reinstalled Laptop")
    assert new_identity.device_id != old_identity.device_id
    assert unlock_with_local_key(layout, VAULT_ID).to_bytes() == original

    # The orphaned old-device record is still listed (never silently
    # dropped), so the user can explicitly revoke it later.
    devices = {d.device_id: d for d in list_devices(layout)}
    assert old_identity.device_id in devices
    assert not devices[old_identity.device_id].is_revoked

    revoke_device(layout, old_identity.device_id)
    devices = {d.device_id: d for d in list_devices(layout)}
    assert devices[old_identity.device_id].is_revoked

    # Revoking the orphan never disturbs the newly enrolled device.
    assert unlock_with_local_key(layout, VAULT_ID).to_bytes() == original


def test_disaster_recovery_survives_secret_service_becoming_unreachable(fake_usb, isolated_xdg, monkeypatch):
    """A slot enrolled while a Secret Service was reachable must still
    fall back cleanly to the password once that service disappears
    (uninstalled, disabled, a different login manager) -- never
    silently substitute a missing pepper."""
    fake_secret = _FakeSecretModuleForThisTest()
    monkeypatch.setattr("passman.core.devices.secret_store._try_import_secret", lambda: fake_secret)

    layout = VaultLayout.at(str(fake_usb), "ASH")
    vms = keyslots.generate_vms()
    original = vms.to_bytes()
    _bootstrap_vault(layout, vms)
    identity, _ = register_device(layout, VAULT_ID, vms, "Laptop")
    assert identity.tier == "secret_service"

    # Secret Service is now gone entirely.
    monkeypatch.setattr("passman.core.devices.secret_store._try_import_secret", lambda: None)

    with pytest.raises(keyslots.SlotUnwrapError):
        unlock_with_local_key(layout, VAULT_ID)

    recovered = unlock_with_password(layout, SecretBytes("master-password"))
    assert recovered.to_bytes() == original


class _FakeSecretModuleForThisTest:
    SchemaAttributeType = type("AttrType", (), {"STRING": "string"})()
    SchemaFlags = type("Flags", (), {"NONE": 0})()
    COLLECTION_DEFAULT = "default"

    class Schema:
        @staticmethod
        def new(name, flags, attr_types):
            return object()

    def __init__(self):
        self._store: dict[tuple, str] = {}

    def _key(self, attributes):
        return tuple(sorted(attributes.items()))

    def password_store_sync(self, schema, attributes, collection, label, password, cancellable):
        self._store[self._key(attributes)] = password
        return True

    def password_lookup_sync(self, schema, attributes, cancellable):
        return self._store.get(self._key(attributes))

    def password_clear_sync(self, schema, attributes, cancellable):
        return self._store.pop(self._key(attributes), None) is not None
