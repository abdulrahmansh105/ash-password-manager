"""Regression tests for resetting the master-password slot through a Local Key."""

from __future__ import annotations

import pytest

from passman.core.crypto import keyslots
from passman.core.devices import registry
from passman.core.security.memory import SecretBytes


def test_local_key_reset_preserves_vms_and_changes_only_password_slot(tmp_path, monkeypatch):
    vault_id = "vault-reset"
    layout = registry.VaultLayout.at(str(tmp_path), ".")
    layout.ensure_dirs()

    monkeypatch.setattr(registry.local_key, "has_local_key", lambda _vault_id: True)
    monkeypatch.setattr(
        registry,
        "unlock_with_local_key",
        lambda _layout, _vault_id: SecretBytes(b"v" * keyslots.VMS_LEN),
    )

    old_password = SecretBytes("old-password")
    new_password = SecretBytes("new-password")
    vms = SecretBytes(b"v" * keyslots.VMS_LEN)
    fast = keyslots.Argon2Params(time_cost=1, memory_cost_kib=8192, parallelism=1)
    old_slot = keyslots.create_password_slot(
        vault_id, keyslots.PASSWORD_SLOT_ID, old_password, vms, params=fast
    )
    registry.write_slot(layout, old_slot)

    registry.reset_master_password_with_local_key(layout, vault_id, new_password, params=fast)

    assert registry.unlock_with_password(layout, new_password).to_bytes() == b"v" * keyslots.VMS_LEN
    with pytest.raises(keyslots.SlotUnwrapError):
        registry.unlock_with_password(layout, old_password)
