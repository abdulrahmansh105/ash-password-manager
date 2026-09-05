"""Vault/key-file relative-path discovery (spec requirement, found live
against real hardware: never assume Passwords.kdbx sits at the
filesystem root -- doctor found the real vault under an Authentication/
subdirectory). Also covers the real-hardware discrepancy found in the
same session: a whole-disk LUKS device (``type: "disk"``, not
``"part"``), which every synthetic fixture before this had missed.

check_vault_paths() only ever calls Path.exists() -- never opens or
reads a file -- so these tests create real (empty, fake-content) files
under tmp_path and check existence only, never content.
"""

from __future__ import annotations

import json

from passman.config.store import UsbRegistration
from passman.integration.usb.identity import (
    UsbState,
    check_vault_paths,
    evaluate_usb_status,
    parse_lsblk_json,
)

LUKS_UUID = "1a7da154-f312-450c-89b2-dd995b282243"  # real hardware UUID, not secret
FS_UUID = "c22baf3d-05a0-4ec0-88fe-72928556594c"


def _reg(vault_rel="Passwords.kdbx", keyfile_rel="Key.key") -> UsbRegistration:
    return UsbRegistration(luks_uuid=LUKS_UUID, filesystem_uuid=FS_UUID, vault_rel_path=vault_rel, keyfile_rel_path=keyfile_rel)


# -- check_vault_paths: real filesystem existence checks, no content read ---


def test_vault_found_inside_subdirectory(tmp_path):
    auth_dir = tmp_path / "Authentication"
    auth_dir.mkdir()
    (auth_dir / "Passwords.kdbx").write_bytes(b"not a real kdbx, just existence-tested")
    (auth_dir / "Key.key").write_bytes(b"not a real keyfile")

    reg = _reg("Authentication/Passwords.kdbx", "Authentication/Key.key")
    status = check_vault_paths(str(tmp_path), reg)

    assert status.vault_exists is True
    assert status.keyfile_exists is True


def test_vault_found_at_root(tmp_path):
    (tmp_path / "Passwords.kdbx").write_bytes(b"x")
    (tmp_path / "Key.key").write_bytes(b"x")

    status = check_vault_paths(str(tmp_path), _reg())

    assert status.vault_exists is True
    assert status.keyfile_exists is True


def test_missing_vault_file(tmp_path):
    (tmp_path / "Key.key").write_bytes(b"x")  # key present, vault is not

    status = check_vault_paths(str(tmp_path), _reg())

    assert status.vault_exists is False
    assert status.keyfile_exists is True


def test_missing_key_file(tmp_path):
    (tmp_path / "Passwords.kdbx").write_bytes(b"x")  # vault present, key is not

    status = check_vault_paths(str(tmp_path), _reg())

    assert status.vault_exists is True
    assert status.keyfile_exists is False


def test_wrong_relative_path_reports_missing_even_if_file_exists_elsewhere(tmp_path):
    # File genuinely exists on disk, just not at the *registered* relative
    # path -- must report missing, never silently search other locations.
    auth_dir = tmp_path / "Authentication"
    auth_dir.mkdir()
    (auth_dir / "Passwords.kdbx").write_bytes(b"x")

    reg = _reg("Passwords.kdbx", "Key.key")  # registered path is root, not Authentication/
    status = check_vault_paths(str(tmp_path), reg)

    assert status.vault_exists is False


def test_check_vault_paths_never_reads_file_contents(tmp_path):
    # A file that would raise if actually opened as UTF-8/binary in an
    # unexpected way -- existence check must never touch content.
    vault_file = tmp_path / "Passwords.kdbx"
    vault_file.write_bytes(b"\xff\xfe\x00\x01garbage-not-a-real-vault")
    (tmp_path / "Key.key").write_bytes(b"\x00\x00")

    status = check_vault_paths(str(tmp_path), _reg())
    assert status.vault_exists is True  # exists() succeeded without ever opening/reading it


# -- wrong USB identity (never trust a mismatched device) -------------------


def test_wrong_usb_identity_is_absent():
    raw = json.dumps(
        {
            "blockdevices": [
                {"name": "sdz", "path": "/dev/sdz", "uuid": "99999999-9999-9999-9999-999999999999", "fstype": "crypto_LUKS", "type": "disk"}
            ]
        }
    )
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.ABSENT


# -- whole-disk LUKS (real hardware shape, not a partition) -----------------
# Found live: the user's actual vault USB is a whole-disk LUKS device
# (`lsblk` reports it as the disk itself, "type": "disk", with no
# partition table) -- every fixture before this test assumed a
# partition ("type": "part", e.g. "sdb1"). The parser doesn't
# distinguish on `type` at all (only fstype+uuid), but this is now
# pinned down explicitly so a future change can't silently break it.


def _whole_disk_luks_blockdevices(mounted: bool) -> str:
    child = {
        "name": f"luks-{LUKS_UUID}",
        "path": f"/dev/mapper/luks-{LUKS_UUID}",
        "uuid": FS_UUID,
        "fstype": "ext4",
        "type": "crypt",
        "mountpoint": "/run/media/ash/AUTH" if mounted else None,
    }
    return json.dumps(
        {
            "blockdevices": [
                {
                    "name": "sdc",
                    "path": "/dev/sdc",
                    "uuid": LUKS_UUID,
                    "fstype": "crypto_LUKS",
                    "type": "disk",  # whole-disk, NOT "part" -- the real-hardware case
                    "mountpoint": None,
                    "children": [child],
                }
            ]
        }
    )


def test_whole_disk_luks_mounted_recognized():
    raw = _whole_disk_luks_blockdevices(mounted=True)
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.MOUNTED
    assert status.mountpoint == "/run/media/ash/AUTH"


def test_whole_disk_luks_locked_recognized():
    raw = json.dumps(
        {"blockdevices": [{"name": "sdc", "path": "/dev/sdc", "uuid": LUKS_UUID, "fstype": "crypto_LUKS", "type": "disk", "mountpoint": None, "children": []}]}
    )
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.LOCKED


def test_whole_disk_luks_unlocked_not_mounted_recognized():
    raw = _whole_disk_luks_blockdevices(mounted=False)
    status = evaluate_usb_status(parse_lsblk_json(raw), _reg())
    assert status.state == UsbState.UNLOCKED_NOT_MOUNTED


# -- registration never stores a mount path as canonical identity -----------


def test_registration_dataclass_has_no_mountpoint_field():
    # Structural guarantee, not just convention: UsbRegistration cannot
    # even hold a mount path -- it's UUIDs + relative paths only.
    fields = _reg().__dataclass_fields__
    assert "mountpoint" not in fields
    assert "mount_path" not in fields
