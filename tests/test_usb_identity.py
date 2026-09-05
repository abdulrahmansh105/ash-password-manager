"""USB identity verification -- pure logic against synthetic ``lsblk -J``
output (fixture data below), no real hardware/subprocess involved.
Exercises spec section 33/34's USB-present / absent / wrong-USB /
wrong-LUKS-device / identity-mismatch cases."""

from __future__ import annotations

import json

from passman.config.store import UsbRegistration
from passman.integration.usb.identity import (
    UsbState,
    UsbStatus,
    evaluate_usb_status,
    parse_lsblk_json,
    should_lock_for_usb_removal,
    should_lock_for_usb_state,
)

LUKS_UUID = "11111111-1111-1111-1111-111111111111"
FS_UUID = "22222222-2222-2222-2222-222222222222"
OTHER_LUKS_UUID = "99999999-9999-9999-9999-999999999999"
WRONG_FS_UUID = "33333333-3333-3333-3333-333333333333"


def _reg() -> UsbRegistration:
    return UsbRegistration(luks_uuid=LUKS_UUID, filesystem_uuid=FS_UUID)


def _lsblk(blockdevices: list[dict]) -> str:
    return json.dumps({"blockdevices": blockdevices})


def test_usb_absent_when_no_matching_luks_uuid():
    raw = _lsblk([{"name": "sda1", "path": "/dev/sda1", "uuid": OTHER_LUKS_UUID, "fstype": "crypto_LUKS", "type": "part"}])
    devices = parse_lsblk_json(raw)
    status = evaluate_usb_status(devices, _reg())
    assert status.state == UsbState.ABSENT


def test_usb_locked_when_present_but_no_unlocked_child():
    raw = _lsblk([{"name": "sdb1", "path": "/dev/sdb1", "uuid": LUKS_UUID, "fstype": "crypto_LUKS", "type": "part", "children": []}])
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.LOCKED


def test_usb_identity_mismatch_when_inner_fs_uuid_differs():
    raw = _lsblk(
        [
            {
                "name": "sdb1",
                "path": "/dev/sdb1",
                "uuid": LUKS_UUID,
                "fstype": "crypto_LUKS",
                "type": "part",
                "children": [
                    {
                        "name": "luks-vault",
                        "path": "/dev/mapper/luks-vault",
                        "uuid": WRONG_FS_UUID,
                        "fstype": "ext4",
                        "type": "crypt",
                        "mountpoint": None,
                    }
                ],
            }
        ]
    )
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.IDENTITY_MISMATCH


def test_usb_unlocked_not_mounted():
    raw = _lsblk(
        [
            {
                "name": "sdb1",
                "path": "/dev/sdb1",
                "uuid": LUKS_UUID,
                "fstype": "crypto_LUKS",
                "type": "part",
                "children": [
                    {"name": "luks-vault", "path": "/dev/mapper/luks-vault", "uuid": FS_UUID, "fstype": "ext4", "type": "crypt", "mountpoint": None}
                ],
            }
        ]
    )
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.UNLOCKED_NOT_MOUNTED
    assert status.mapped_device_path == "/dev/mapper/luks-vault"


def test_usb_mounted():
    raw = _lsblk(
        [
            {
                "name": "sdb1",
                "path": "/dev/sdb1",
                "uuid": LUKS_UUID,
                "fstype": "crypto_LUKS",
                "type": "part",
                "children": [
                    {
                        "name": "luks-vault",
                        "path": "/dev/mapper/luks-vault",
                        "uuid": FS_UUID,
                        "fstype": "ext4",
                        "type": "crypt",
                        "mountpoint": "/run/media/ash/vault",
                    }
                ],
            }
        ]
    )
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.MOUNTED
    assert status.mountpoint == "/run/media/ash/vault"


def test_filesystem_label_alone_is_never_trusted():
    # Even if a device carries the "right-looking" label, without a
    # matching LUKS UUID it must never be treated as the registered USB.
    raw = _lsblk(
        [{"name": "sdc1", "path": "/dev/sdc1", "uuid": OTHER_LUKS_UUID, "fstype": "crypto_LUKS", "type": "part", "label": "Passwords"}]
    )
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.ABSENT


# -- should_lock_for_usb_state: the pure decision behind "USB removal
# must trigger immediate lock" (tested here against synthetic/mocked
# device-status values, per the explicit requirement to prove this with
# mocked events before ever touching live hardware) ------------------


def test_lock_required_when_device_becomes_absent():
    assert should_lock_for_usb_state(UsbStatus(state=UsbState.ABSENT), "/run/media/ash/vault") is True


def test_lock_required_when_device_becomes_locked_again():
    assert should_lock_for_usb_state(UsbStatus(state=UsbState.LOCKED), "/run/media/ash/vault") is True


def test_lock_required_when_identity_mismatch_appears():
    assert (
        should_lock_for_usb_state(UsbStatus(state=UsbState.IDENTITY_MISMATCH), "/run/media/ash/vault")
        is True
    )


def test_lock_required_when_unmounted_but_still_unlocked():
    assert (
        should_lock_for_usb_state(UsbStatus(state=UsbState.UNLOCKED_NOT_MOUNTED), "/run/media/ash/vault")
        is True
    )


def test_no_lock_when_still_mounted_at_expected_path():
    status = UsbStatus(state=UsbState.MOUNTED, mountpoint="/run/media/ash/vault")
    assert should_lock_for_usb_state(status, "/run/media/ash/vault") is False


def test_lock_required_when_mounted_at_a_different_path():
    # Fail-closed: even "mounted" isn't trusted unless it's mounted at
    # exactly the path the vault was actually opened from.
    status = UsbStatus(state=UsbState.MOUNTED, mountpoint="/run/media/ash/somewhere-else")
    assert should_lock_for_usb_state(status, "/run/media/ash/vault") is True


def test_simulated_removal_sequence_locks_exactly_once_when_it_happens():
    # Simulates a sequence of poll ticks: mounted, mounted, then a
    # mocked "USB physically removed" event (ABSENT), then it stays
    # absent -- the lock decision must flip to True exactly at removal
    # and stay True, never flip back to False on its own.
    mounted = UsbStatus(state=UsbState.MOUNTED, mountpoint="/run/media/ash/vault")
    absent = UsbStatus(state=UsbState.ABSENT)
    sequence = [mounted, mounted, mounted, absent, absent]
    decisions = [should_lock_for_usb_state(s, "/run/media/ash/vault") for s in sequence]
    assert decisions == [False, False, False, True, True]


# -- should_lock_for_usb_removal: the same pure signal, gated by the
# user's configured "When USB is removed" policy (spec section 10).
# Regression coverage for the bug where this dropdown was saved but
# never actually consulted by the lock logic. ------------------------


def test_lock_immediately_locks_on_removal_exactly_like_the_ungated_signal():
    absent = UsbStatus(state=UsbState.ABSENT)
    assert should_lock_for_usb_removal(absent, "/run/media/ash/vault", "lock_immediately") is True


def test_keep_unlocked_never_locks_on_removal():
    absent = UsbStatus(state=UsbState.ABSENT)
    assert should_lock_for_usb_removal(absent, "/run/media/ash/vault", "keep_unlocked") is False


def test_keep_unlocked_never_locks_even_on_identity_mismatch_or_wrong_mountpoint():
    mismatch = UsbStatus(state=UsbState.IDENTITY_MISMATCH)
    wrong_mount = UsbStatus(state=UsbState.MOUNTED, mountpoint="/run/media/ash/somewhere-else")
    assert should_lock_for_usb_removal(mismatch, "/run/media/ash/vault", "keep_unlocked") is False
    assert should_lock_for_usb_removal(wrong_mount, "/run/media/ash/vault", "keep_unlocked") is False


def test_both_policies_agree_while_the_usb_stays_correctly_mounted():
    # Neither policy should ever lock while nothing has actually
    # changed -- the policy only matters once a removal is detected.
    mounted = UsbStatus(state=UsbState.MOUNTED, mountpoint="/run/media/ash/vault")
    assert should_lock_for_usb_removal(mounted, "/run/media/ash/vault", "lock_immediately") is False
    assert should_lock_for_usb_removal(mounted, "/run/media/ash/vault", "keep_unlocked") is False


def test_simulated_removal_sequence_respects_keep_unlocked_throughout():
    mounted = UsbStatus(state=UsbState.MOUNTED, mountpoint="/run/media/ash/vault")
    absent = UsbStatus(state=UsbState.ABSENT)
    sequence = [mounted, mounted, absent, absent, absent]
    decisions = [should_lock_for_usb_removal(s, "/run/media/ash/vault", "keep_unlocked") for s in sequence]
    assert decisions == [False, False, False, False, False]


def test_simulated_removal_sequence_still_locks_under_lock_immediately():
    mounted = UsbStatus(state=UsbState.MOUNTED, mountpoint="/run/media/ash/vault")
    absent = UsbStatus(state=UsbState.ABSENT)
    sequence = [mounted, mounted, absent, absent, absent]
    decisions = [should_lock_for_usb_removal(s, "/run/media/ash/vault", "lock_immediately") for s in sequence]
    assert decisions == [False, False, True, True, True]


# -- Plain (non-LUKS) filesystem vaults: the shape the new multi-vault
# Sign-in wizard produces by default for an ordinary, unencrypted USB
# stick. Regression coverage for the bug where such a vault -- genuinely
# connected and mounted -- was always reported ABSENT here (this module
# only ever looked for a LUKS container), which under the default
# "lock_immediately" policy self-locked it within one poll tick of every
# successful unlock. ---------------------------------------------------

PLAIN_FS_UUID = "44444444-4444-4444-4444-444444444444"
OTHER_PLAIN_FS_UUID = "55555555-5555-5555-5555-555555555555"


def _plain_reg() -> UsbRegistration:
    # luks_uuid="" (falsy), exactly what a plain-filesystem VaultRecord
    # looks like -- UsbRegistration itself requires the field, but the
    # dispatch in evaluate_usb_status only ever checks truthiness, so
    # this is a faithful stand-in for that duck-typed case.
    return UsbRegistration(luks_uuid="", filesystem_uuid=PLAIN_FS_UUID)


def test_plain_filesystem_mounted_and_genuinely_connected():
    raw = _lsblk([{"name": "sdb1", "path": "/dev/sdb1", "uuid": PLAIN_FS_UUID, "fstype": "ext4", "type": "part", "mountpoint": "/run/media/ash/vault"}])
    status = evaluate_usb_status(parse_lsblk_json(raw), _plain_reg())
    assert status.state == UsbState.MOUNTED
    assert status.mountpoint == "/run/media/ash/vault"
    assert status.mapped_device_path == "/dev/sdb1"


def test_plain_filesystem_present_but_not_mounted():
    raw = _lsblk([{"name": "sdb1", "path": "/dev/sdb1", "uuid": PLAIN_FS_UUID, "fstype": "ext4", "type": "part", "mountpoint": None}])
    status = evaluate_usb_status(parse_lsblk_json(raw), _plain_reg())
    assert status.state == UsbState.PRESENT_NOT_MOUNTED
    assert status.mapped_device_path == "/dev/sdb1"


def test_plain_filesystem_absent_when_no_matching_uuid():
    raw = _lsblk([{"name": "sdc1", "path": "/dev/sdc1", "uuid": OTHER_PLAIN_FS_UUID, "fstype": "vfat", "type": "part", "mountpoint": "/run/media/ash/other"}])
    status = evaluate_usb_status(parse_lsblk_json(raw), _plain_reg())
    assert status.state == UsbState.ABSENT


def test_plain_filesystem_wrong_usb_is_not_matched_even_if_mounted():
    # The literal "wrong USB" case: something is connected and mounted,
    # just not the registered vault's own device.
    raw = _lsblk([{"name": "sdz1", "path": "/dev/sdz1", "uuid": OTHER_PLAIN_FS_UUID, "fstype": "ext4", "type": "part", "mountpoint": "/run/media/ash/decoy"}])
    status = evaluate_usb_status(parse_lsblk_json(raw), _plain_reg())
    assert status.state == UsbState.ABSENT


def test_plain_filesystem_never_matches_a_luks_containers_own_uuid():
    # Defensive: a LUKS container's reported "uuid" is its own outer
    # LUKS UUID, never an inner filesystem's -- even if it coincidentally
    # equals the registered plain filesystem_uuid, it must not be
    # treated as a match (never trust a coincidental identity match).
    raw = _lsblk([{"name": "sdb1", "path": "/dev/sdb1", "uuid": PLAIN_FS_UUID, "fstype": "crypto_LUKS", "type": "part"}])
    status = evaluate_usb_status(parse_lsblk_json(raw), _plain_reg())
    assert status.state == UsbState.ABSENT


def test_luks_registration_is_unaffected_by_unrelated_plain_devices_present():
    # Regression guard: a LUKS-registered vault's own detection must be
    # completely unaffected by other, unrelated plain-filesystem devices
    # also being present on the system (e.g. the user's normal internal
    # drives) -- no regression to LUKS2 detection from adding the
    # plain-filesystem branch.
    raw = _lsblk(
        [
            {"name": "nvme0n1p1", "path": "/dev/nvme0n1p1", "uuid": "unrelated-internal-disk", "fstype": "ext4", "type": "part"},
            {
                "name": "sdb1", "path": "/dev/sdb1", "uuid": LUKS_UUID, "fstype": "crypto_LUKS", "type": "part",
                "children": [
                    {"name": "luks-vault", "path": "/dev/mapper/luks-vault", "uuid": FS_UUID, "fstype": "ext4", "type": "crypt", "mountpoint": "/run/media/ash/vault"}
                ],
            },
        ]
    )
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.MOUNTED
    assert status.mountpoint == "/run/media/ash/vault"


def test_lock_required_when_plain_filesystem_present_but_not_mounted():
    status = UsbStatus(state=UsbState.PRESENT_NOT_MOUNTED)
    assert should_lock_for_usb_state(status, "/run/media/ash/vault") is True


def test_no_lock_when_plain_filesystem_mounted_at_expected_path():
    status = UsbStatus(state=UsbState.MOUNTED, mountpoint="/run/media/ash/vault")
    assert should_lock_for_usb_removal(status, "/run/media/ash/vault", "lock_immediately") is False


def test_keep_unlocked_also_applies_to_a_plain_filesystem_becoming_absent():
    absent = UsbStatus(state=UsbState.ABSENT)
    assert should_lock_for_usb_removal(absent, "/run/media/ash/vault", "keep_unlocked") is False


def test_unrelated_devices_are_ignored():
    raw = _lsblk(
        [
            {"name": "nvme0n1", "path": "/dev/nvme0n1", "uuid": None, "fstype": None, "type": "disk", "children": [
                {"name": "nvme0n1p1", "path": "/dev/nvme0n1p1", "uuid": "aaaa", "fstype": "vfat", "type": "part"},
            ]},
        ]
    )
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.ABSENT
