"""Tests for integration.usb.udisks2's pure data-transformation
functions (spec sections 2, 29, 30) using synthetic fixtures -- no
live D-Bus/UDisks2 connection required, matching the existing style of
tests/test_usb_identity.py's synthetic ``lsblk`` fixtures. A live smoke
test against the real UDisks2 service is included separately, skipped
automatically when unavailable."""

from __future__ import annotations

import pytest

from passman.integration.usb.identity import UsbState, evaluate_usb_status, should_lock_for_usb_state
from passman.integration.usb.udisks2 import (
    RawBlockInfo,
    RawDriveInfo,
    Udisks2Unavailable,
    build_block_device_tree,
    format_size,
    is_available,
    is_removable_drive,
    list_block_devices,
    list_drive_choices,
)
from passman.core.vaults.registry import VaultRecord


def _drive(**overrides) -> RawDriveInfo:
    defaults = dict(
        object_path="/org/freedesktop/UDisks2/drives/d0",
        vendor="Kingston",
        model="DataTraveler 2.0",
        serial="1C6F654E",
        size=15_500_083_200,
        connection_bus="usb",
        removable=True,
        ejectable=True,
        optical=False,
    )
    defaults.update(overrides)
    return RawDriveInfo(**defaults)


def _block(**overrides) -> RawBlockInfo:
    defaults = dict(
        object_path="/org/freedesktop/UDisks2/block_devices/sdc",
        device="/dev/sdc",
        id_type="",
        id_uuid="",
        id_label="",
        id_usage="",
        size=15_500_083_200,
        read_only=False,
        drive_object_path="/org/freedesktop/UDisks2/drives/d0",
        crypto_backing_device=None,
        mountpoints=(),
        cleartext_object_path=None,
    )
    defaults.update(overrides)
    return RawBlockInfo(**defaults)


def test_format_size_bytes():
    assert format_size(500) == "500 B"


def test_format_size_kb_mb_gb():
    assert format_size(2_000) == "2.0 KB"
    assert format_size(64_000_000) == "64.0 MB"
    assert format_size(15_500_083_200) == "15.5 GB"


def test_is_removable_drive_true_for_usb():
    assert is_removable_drive(_drive(connection_bus="usb")) is True


def test_is_removable_drive_false_for_internal_sata():
    assert is_removable_drive(_drive(connection_bus="", removable=False, ejectable=False)) is False


def test_is_removable_drive_false_for_optical_even_if_ejectable():
    """Verified against this project's own development machine: an
    internal optical drive reports removable=True/ejectable=True over
    UDisks2 -- connection-bus and the optical flag, not
    removable/ejectable, are what must gate the picker."""
    assert is_removable_drive(_drive(connection_bus="", removable=True, ejectable=True, optical=True)) is False


def test_list_drive_choices_filters_and_labels():
    drives = [
        _drive(object_path="/drives/usb1", vendor="SanDisk", model="Ultra", size=64_000_000_000, connection_bus="usb"),
        _drive(object_path="/drives/internal", vendor="", model="WDC WD10", connection_bus="", removable=False),
        _drive(object_path="/drives/optical", vendor="", model="DVD-RW", connection_bus="", optical=True),
    ]
    choices = list_drive_choices(drives)
    assert len(choices) == 1
    assert choices[0].object_path == "/drives/usb1"
    assert choices[0].label == "SanDisk Ultra (64.0 GB)"


def test_list_drive_choices_unknown_vendor_model_still_shown():
    drives = [_drive(vendor="", model="", connection_bus="usb")]
    choices = list_drive_choices(drives)
    assert len(choices) == 1
    assert choices[0].label.startswith("Unknown USB drive")


def test_build_tree_locked_luks_has_no_children():
    blocks = [_block(id_type="crypto_LUKS", id_uuid="luks-uuid-1", crypto_backing_device=None)]
    tree = build_block_device_tree(blocks)
    assert len(tree) == 1
    assert tree[0].fstype == "crypto_LUKS"
    assert tree[0].uuid == "luks-uuid-1"
    assert tree[0].children == ()


def test_build_tree_unlocked_luks_has_crypt_child_with_mountpoint():
    luks_block = _block(
        object_path="/blocks/sdc",
        device="/dev/sdc",
        id_type="crypto_LUKS",
        id_uuid="luks-uuid-1",
        cleartext_object_path="/blocks/dm-0",
    )
    cleartext_block = _block(
        object_path="/blocks/dm-0",
        device="/dev/dm-0",
        id_type="ext4",
        id_uuid="fs-uuid-1",
        crypto_backing_device="/blocks/sdc",
        mountpoints=("/media/user/ASH",),
    )
    tree = build_block_device_tree([luks_block, cleartext_block])
    assert len(tree) == 1  # the cleartext block is a child, not a second root
    root = tree[0]
    assert root.uuid == "luks-uuid-1"
    assert len(root.children) == 1
    child = root.children[0]
    assert child.type == "crypt"
    assert child.uuid == "fs-uuid-1"
    assert child.mountpoint == "/media/user/ASH"


def test_build_tree_feeds_directly_into_existing_identity_logic():
    """The whole point of reusing BlockDevice: no adapter needed for
    evaluate_usb_status/should_lock_for_usb_state."""
    luks_block = _block(
        object_path="/blocks/sdc", device="/dev/sdc", id_type="crypto_LUKS", id_uuid="luks-uuid-1",
        cleartext_object_path="/blocks/dm-0",
    )
    cleartext_block = _block(
        object_path="/blocks/dm-0", device="/dev/dm-0", id_type="ext4", id_uuid="fs-uuid-1",
        crypto_backing_device="/blocks/sdc", mountpoints=("/media/user/ASH",),
    )
    devices = build_block_device_tree([luks_block, cleartext_block])
    record = VaultRecord(vault_id="v1", name="A", filesystem_uuid="fs-uuid-1", luks_uuid="luks-uuid-1")

    status = evaluate_usb_status(devices, record)
    assert status.state == UsbState.MOUNTED
    assert status.mountpoint == "/media/user/ASH"
    assert should_lock_for_usb_state(status, "/media/user/ASH") is False
    assert should_lock_for_usb_state(status, "/some/other/path") is True


def test_build_tree_wrong_filesystem_uuid_is_identity_mismatch():
    luks_block = _block(
        object_path="/blocks/sdc", device="/dev/sdc", id_type="crypto_LUKS", id_uuid="luks-uuid-1",
        cleartext_object_path="/blocks/dm-0",
    )
    cleartext_block = _block(
        object_path="/blocks/dm-0", device="/dev/dm-0", id_type="ext4", id_uuid="a-different-fs-uuid",
        crypto_backing_device="/blocks/sdc", mountpoints=("/media/user/ASH",),
    )
    devices = build_block_device_tree([luks_block, cleartext_block])
    record = VaultRecord(vault_id="v1", name="A", filesystem_uuid="fs-uuid-1", luks_uuid="luks-uuid-1")

    status = evaluate_usb_status(devices, record)
    assert status.state == UsbState.IDENTITY_MISMATCH


def test_build_tree_plain_non_luks_filesystem_is_a_disk_root():
    plain_block = _block(id_type="vfat", id_uuid="fs-uuid-plain", mountpoints=("/media/user/PLAIN",))
    tree = build_block_device_tree([plain_block])
    assert len(tree) == 1
    assert tree[0].type == "disk"
    assert tree[0].fstype == "vfat"
    assert tree[0].mountpoint == "/media/user/PLAIN"


# --- live smoke test: real UDisks2, skipped automatically if unreachable ---


def test_live_udisks2_enumeration_does_not_raise():
    from passman.integration.usb.udisks2 import list_removable_drive_choices

    try:
        drives = list_removable_drive_choices()
    except Udisks2Unavailable:
        pytest.skip("UDisks2 is not reachable in this environment")
    assert isinstance(drives, list)


def test_live_udisks2_list_block_devices_does_not_raise():
    if not is_available():
        pytest.skip("UDisks2 is not reachable in this environment")
    devices = list_block_devices()
    assert isinstance(devices, list)
