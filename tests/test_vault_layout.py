"""Tests for core.vaults.layout -- traversal-safe on-USB path
resolution (spec section 21)."""

from __future__ import annotations

import pytest

from passman.core.vaults.layout import PathTraversalError, VaultLayout


def test_layout_paths_are_under_container(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    assert layout.container_dir == (fake_usb / "ASH").resolve()
    assert layout.kdbx_path == layout.container_dir / "Passwords.kdbx"
    assert layout.keyfile_path == layout.container_dir / "Key.key"
    assert layout.vault_json == layout.container_dir / "vault.json"
    assert layout.devices_json == layout.container_dir / "devices.json"
    assert layout.keyslots_dir == layout.container_dir / "keyslots"


def test_keyslot_path_rejects_traversal_in_slot_id(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    with pytest.raises(PathTraversalError):
        layout.keyslot_path("../../etc/passwd")


def test_keyslot_path_rejects_dot_and_dotdot(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    for bad in (".", ".."):
        with pytest.raises(PathTraversalError):
            layout.keyslot_path(bad)


def test_container_rel_path_traversal_is_rejected(fake_usb):
    with pytest.raises(PathTraversalError):
        VaultLayout.at(str(fake_usb), "../../etc")


def test_exists_false_until_vault_and_kdbx_present(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    assert not layout.exists()
    layout.ensure_dirs()
    layout.kdbx_path.write_bytes(b"not-a-real-kdbx")
    assert not layout.exists()  # vault.json still missing
    layout.vault_json.write_text("{}")
    assert layout.exists()


def test_is_legacy_kdbx_only(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "Authentication")
    layout.ensure_dirs()
    layout.kdbx_path.write_bytes(b"legacy-kdbx-bytes")
    assert layout.is_legacy_kdbx_only()
    layout.vault_json.write_text("{}")
    assert not layout.is_legacy_kdbx_only()


def test_ensure_dirs_creates_all_subdirectories(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    layout.ensure_dirs()
    assert layout.container_dir.is_dir()
    assert layout.keyslots_dir.is_dir()
    assert layout.icons_dir.is_dir()
    assert layout.backups_dir.is_dir()
