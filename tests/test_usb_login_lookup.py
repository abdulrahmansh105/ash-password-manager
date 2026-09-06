"""Tests for core.flows.usb_login_lookup -- matching a registered
vault to a currently-connected USB (spec sections 1, 27, 30), with all
UDisks2/udisksctl I/O monkeypatched."""

from __future__ import annotations

from passman.core.flows.usb_login_lookup import (
    find_and_mount_vault,
    find_connected_vault,
)
from passman.core.vaults.registry import VaultRecord
from passman.integration.usb.udisks2 import RawBlockInfo


def _block(**overrides) -> RawBlockInfo:
    defaults = dict(
        object_path="/blocks/x", device="/dev/sdx", id_type="", id_uuid="", id_label="", id_usage="",
        size=0, read_only=False, drive_object_path="/drives/x", crypto_backing_device=None,
        mountpoints=(), cleartext_object_path=None,
    )
    defaults.update(overrides)
    return RawBlockInfo(**defaults)


def _record(**overrides) -> VaultRecord:
    defaults = dict(vault_id="v1", name="Test", filesystem_uuid="fs-1")
    defaults.update(overrides)
    return VaultRecord(**defaults)


def test_plain_filesystem_vault_not_connected_returns_none(monkeypatch):
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], []))
    assert find_and_mount_vault(_record(filesystem_uuid="fs-missing")) is None


def test_plain_filesystem_vault_connected_and_already_mounted(monkeypatch):
    fs_block = _block(id_usage="filesystem", id_uuid="fs-1", mountpoints=("/media/user/ASH",))
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))
    mount_calls = []
    monkeypatch.setattr("passman.core.flows.usb_login_lookup.udisks_mount", lambda dev: mount_calls.append(dev))

    mountpoint = find_and_mount_vault(_record(filesystem_uuid="fs-1"))
    assert mountpoint == "/media/user/ASH"
    assert mount_calls == []  # already mounted -- mount() must not be called


def test_plain_filesystem_vault_connected_needs_mount(monkeypatch):
    fs_block = _block(id_usage="filesystem", id_uuid="fs-1", mountpoints=())
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))
    monkeypatch.setattr("passman.core.flows.usb_login_lookup.udisks_mount", lambda dev: "/media/user/NEW")

    assert find_and_mount_vault(_record(filesystem_uuid="fs-1")) == "/media/user/NEW"


def test_luks_vault_not_connected_never_calls_unlock(monkeypatch):
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], []))
    unlock_calls = []
    monkeypatch.setattr("passman.core.flows.usb_login_lookup.udisks_unlock", lambda dev: unlock_calls.append(dev) or True)

    result = find_and_mount_vault(_record(luks_uuid="luks-1", filesystem_uuid="fs-1"))
    assert result is None
    assert unlock_calls == []  # the whole point: never prompt speculatively


def test_luks_vault_present_but_locked_unlocks_then_mounts(monkeypatch):
    luks_block = _block(object_path="/blocks/sdc", device="/dev/sdc", id_usage="crypto", id_uuid="luks-1")
    cleartext_block = _block(
        object_path="/blocks/dm-0", device="/dev/dm-0", id_usage="filesystem", id_uuid="fs-1",
        crypto_backing_device="/blocks/sdc", mountpoints=("/media/user/ASH",),
    )
    snapshots = [([], [luks_block]), ([], [luks_block, cleartext_block])]
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: snapshots.pop(0))
    unlock_calls = []
    monkeypatch.setattr("passman.core.flows.usb_login_lookup.udisks_unlock", lambda dev: unlock_calls.append(dev) or True)

    result = find_and_mount_vault(_record(luks_uuid="luks-1", filesystem_uuid="fs-1"))
    assert result == "/media/user/ASH"
    assert unlock_calls == ["/dev/sdc"]


def test_luks_vault_already_unlocked_skips_unlock_call(monkeypatch):
    luks_block = _block(object_path="/blocks/sdc", device="/dev/sdc", id_usage="crypto", id_uuid="luks-1")
    cleartext_block = _block(
        object_path="/blocks/dm-0", device="/dev/dm-0", id_usage="filesystem", id_uuid="fs-1",
        crypto_backing_device="/blocks/sdc", mountpoints=("/media/user/ASH",),
    )
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr(
        "passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [luks_block, cleartext_block])
    )
    unlock_calls = []
    monkeypatch.setattr("passman.core.flows.usb_login_lookup.udisks_unlock", lambda dev: unlock_calls.append(dev) or True)

    result = find_and_mount_vault(_record(luks_uuid="luks-1", filesystem_uuid="fs-1"))
    assert result == "/media/user/ASH"
    assert unlock_calls == []


def test_luks_vault_wrong_inner_filesystem_is_identity_mismatch(monkeypatch):
    luks_block = _block(object_path="/blocks/sdc", device="/dev/sdc", id_usage="crypto", id_uuid="luks-1")
    cleartext_block = _block(
        object_path="/blocks/dm-0", device="/dev/dm-0", id_usage="filesystem", id_uuid="a-different-fs-uuid",
        crypto_backing_device="/blocks/sdc", mountpoints=("/media/user/ASH",),
    )
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr(
        "passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [luks_block, cleartext_block])
    )

    assert find_and_mount_vault(_record(luks_uuid="luks-1", filesystem_uuid="fs-1")) is None


def test_luks_unlock_failure_returns_none(monkeypatch):
    luks_block = _block(object_path="/blocks/sdc", device="/dev/sdc", id_usage="crypto", id_uuid="luks-1")
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [luks_block]))
    monkeypatch.setattr("passman.core.flows.usb_login_lookup.udisks_unlock", lambda dev: False)

    assert find_and_mount_vault(_record(luks_uuid="luks-1", filesystem_uuid="fs-1")) is None


def test_find_connected_vault_tries_each_in_turn_and_stops_at_first_match(monkeypatch):
    fs_block = _block(id_usage="filesystem", id_uuid="fs-2", mountpoints=("/media/user/SECOND",))
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))

    vault_a = _record(vault_id="a", filesystem_uuid="fs-1")  # not connected
    vault_b = _record(vault_id="b", filesystem_uuid="fs-2")  # connected
    vault_c = _record(vault_id="c", filesystem_uuid="fs-3")  # not connected

    result = find_connected_vault([vault_a, vault_b, vault_c])
    assert result == (vault_b, "/media/user/SECOND")


def test_find_connected_vault_returns_none_when_none_connected(monkeypatch):
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], []))
    assert find_connected_vault([_record()]) is None


def test_find_connected_vault_empty_list_returns_none():
    assert find_connected_vault([]) is None
