"""Tests for core.flows.usb_setup -- the setup wizard's USB pick/
unlock/mount orchestration (spec section 2). ``pick_usable_block`` and
``detect_container_kind`` are pure/filesystem-only and tested directly
against synthetic fixtures; ``prepare_mountpoint``'s I/O
(``udisks2.new_client``/``snapshot_from_client``, ``udisksctl``
unlock/mount) is monkeypatched, matching this project's existing fake-
dependency test idiom."""

from __future__ import annotations

import pytest

from passman.core.flows.usb_setup import (
    SetupUsbError,
    detect_container_kind,
    discover_container,
    pick_usable_block,
    prepare_mountpoint,
)
from passman.integration.usb.udisks2 import RawBlockInfo


def _block(**overrides) -> RawBlockInfo:
    defaults = dict(
        object_path="/blocks/x",
        device="/dev/sdx",
        id_type="",
        id_uuid="",
        id_label="",
        id_usage="",
        size=0,
        read_only=False,
        drive_object_path="/drives/x",
        crypto_backing_device=None,
        mountpoints=(),
        cleartext_object_path=None,
    )
    defaults.update(overrides)
    return RawBlockInfo(**defaults)


def test_pick_usable_block_prefers_crypto_or_filesystem():
    blank_partition_table_entry = _block(id_usage="")
    real_fs = _block(id_usage="filesystem", id_uuid="fs-1")
    assert pick_usable_block([blank_partition_table_entry, real_fs]) is real_fs


def test_pick_usable_block_returns_none_when_nothing_usable():
    assert pick_usable_block([_block(id_usage="")]) is None


def test_pick_usable_block_accepts_crypto():
    luks = _block(id_usage="crypto", id_type="crypto_LUKS", id_uuid="luks-1")
    assert pick_usable_block([luks]) is luks


def test_detect_container_kind_empty(fake_usb):
    assert detect_container_kind(str(fake_usb), "ASH") == "empty"


def test_detect_container_kind_foreign_kdbx(fake_usb):
    from passman.core.vaults.layout import VaultLayout

    layout = VaultLayout.at(str(fake_usb), "Authentication")
    layout.ensure_dirs()
    layout.kdbx_path.write_bytes(b"legacy-kdbx")
    assert detect_container_kind(str(fake_usb), "Authentication") == "foreign"


def test_detect_container_kind_ash_vault(fake_usb):
    from passman.core.vaults.layout import VaultLayout

    layout = VaultLayout.at(str(fake_usb), "ASH")
    layout.ensure_dirs()
    layout.kdbx_path.write_bytes(b"kdbx")
    layout.vault_json.write_text("{}")
    assert detect_container_kind(str(fake_usb), "ASH") == "ash"


def test_discover_container_empty_usb_defaults_to_ash(fake_usb):
    assert discover_container(str(fake_usb)) == ("ASH", "empty")


def test_discover_container_finds_ash_vault_at_default_path(fake_usb):
    from passman.core.vaults.layout import VaultLayout

    layout = VaultLayout.at(str(fake_usb), "ASH")
    layout.ensure_dirs()
    layout.kdbx_path.write_bytes(b"kdbx")
    layout.vault_json.write_text("{}")

    assert discover_container(str(fake_usb)) == ("ASH", "ash")


def test_discover_container_finds_legacy_vault_at_a_different_path(fake_usb):
    """The real-world case this bug fix targets: an existing vault
    (e.g. a legacy single-vault registration) sitting at some other
    container name, never "ASH", must still be found automatically."""
    from passman.core.vaults.layout import VaultLayout

    layout = VaultLayout.at(str(fake_usb), "Authentication")
    layout.ensure_dirs()
    layout.kdbx_path.write_bytes(b"legacy-kdbx")

    assert discover_container(str(fake_usb)) == ("Authentication", "foreign")


def test_discover_container_finds_ash_vault_at_a_different_path(fake_usb):
    from passman.core.vaults.layout import VaultLayout

    layout = VaultLayout.at(str(fake_usb), "MyVault")
    layout.ensure_dirs()
    layout.kdbx_path.write_bytes(b"kdbx")
    layout.vault_json.write_text("{}")

    assert discover_container(str(fake_usb)) == ("MyVault", "ash")


def test_discover_container_prefers_ash_over_other_directories(fake_usb):
    from passman.core.vaults.layout import VaultLayout

    ash_layout = VaultLayout.at(str(fake_usb), "ASH")
    ash_layout.ensure_dirs()
    ash_layout.kdbx_path.write_bytes(b"kdbx")
    ash_layout.vault_json.write_text("{}")

    other_layout = VaultLayout.at(str(fake_usb), "Authentication")
    other_layout.ensure_dirs()
    other_layout.kdbx_path.write_bytes(b"legacy-kdbx")

    assert discover_container(str(fake_usb)) == ("ASH", "ash")


def test_discover_container_ignores_unrelated_empty_directories(fake_usb):
    (fake_usb / "icons").mkdir()
    (fake_usb / "some-other-folder").mkdir()
    assert discover_container(str(fake_usb)) == ("ASH", "empty")


def test_prepare_mountpoint_plain_filesystem_already_mounted(monkeypatch):
    plain_fs = _block(
        object_path="/blocks/sdb1", device="/dev/sdb1", id_usage="filesystem", id_uuid="fs-uuid-1",
        drive_object_path="/drives/d0", mountpoints=("/media/user/USB",),
    )
    monkeypatch.setattr(
        "passman.integration.usb.udisks2.new_client", lambda: object()
    )
    monkeypatch.setattr(
        "passman.integration.usb.udisks2.snapshot_from_client", lambda client: ([], [plain_fs])
    )
    mount_calls = []
    monkeypatch.setattr("passman.integration.usb.udisks.mount", lambda dev: mount_calls.append(dev) or "/should-not-be-used")

    identity, mountpoint = prepare_mountpoint("/drives/d0", "SanDisk", "Ultra")

    assert mountpoint == "/media/user/USB"  # already mounted -- mount() must not be called
    assert mount_calls == []
    assert identity.luks_uuid is None
    assert identity.filesystem_uuid == "fs-uuid-1"
    assert identity.drive_vendor == "SanDisk"


def test_prepare_mountpoint_plain_filesystem_needs_mounting(monkeypatch):
    plain_fs = _block(
        object_path="/blocks/sdb1", device="/dev/sdb1", id_usage="filesystem", id_uuid="fs-uuid-1",
        drive_object_path="/drives/d0", mountpoints=(),
    )
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda client: ([], [plain_fs]))
    monkeypatch.setattr("passman.integration.usb.udisks.mount", lambda dev: "/media/user/NEWMOUNT" if dev == "/dev/sdb1" else None)

    identity, mountpoint = prepare_mountpoint("/drives/d0", "SanDisk", "Ultra")
    assert mountpoint == "/media/user/NEWMOUNT"


def test_prepare_mountpoint_luks_unlocks_then_finds_cleartext(monkeypatch):
    luks_block = _block(
        object_path="/blocks/sdc", device="/dev/sdc", id_usage="crypto", id_type="crypto_LUKS",
        id_uuid="luks-uuid-1", drive_object_path="/drives/d0",
    )
    cleartext_block = _block(
        object_path="/blocks/dm-0", device="/dev/dm-0", id_usage="filesystem", id_uuid="fs-uuid-2",
        crypto_backing_device="/blocks/sdc", mountpoints=("/media/user/ASH",),
    )

    snapshots = [([], [luks_block]), ([], [luks_block, cleartext_block])]

    def fake_snapshot(client):
        return snapshots.pop(0) if snapshots else ([], [luks_block, cleartext_block])

    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", fake_snapshot)
    unlock_calls = []
    monkeypatch.setattr("passman.integration.usb.udisks.unlock", lambda dev: unlock_calls.append(dev) or True)

    identity, mountpoint = prepare_mountpoint("/drives/d0", "Kingston", "DataTraveler")

    assert unlock_calls == ["/dev/sdc"]
    assert identity.luks_uuid == "luks-uuid-1"
    assert identity.filesystem_uuid == "fs-uuid-2"
    assert mountpoint == "/media/user/ASH"


def test_prepare_mountpoint_no_usable_block_raises(monkeypatch):
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda client: ([], []))
    with pytest.raises(SetupUsbError):
        prepare_mountpoint("/drives/nonexistent", "Vendor", "Model")


def test_prepare_mountpoint_unlock_failure_raises(monkeypatch):
    luks_block = _block(
        object_path="/blocks/sdc", device="/dev/sdc", id_usage="crypto", id_type="crypto_LUKS",
        id_uuid="luks-uuid-1", drive_object_path="/drives/d0",
    )
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda client: ([], [luks_block]))
    monkeypatch.setattr("passman.integration.usb.udisks.unlock", lambda dev: False)

    with pytest.raises(SetupUsbError):
        prepare_mountpoint("/drives/d0", "Kingston", "DataTraveler")


def test_prepare_mountpoint_mount_failure_raises(monkeypatch):
    plain_fs = _block(
        object_path="/blocks/sdb1", device="/dev/sdb1", id_usage="filesystem", id_uuid="fs-uuid-1",
        drive_object_path="/drives/d0", mountpoints=(),
    )
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda client: ([], [plain_fs]))
    monkeypatch.setattr("passman.integration.usb.udisks.mount", lambda dev: None)

    with pytest.raises(SetupUsbError):
        prepare_mountpoint("/drives/d0", "SanDisk", "Ultra")
