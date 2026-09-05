"""Tests for core.backup.archive (spec section 15): what is and is not
included, round-trip correctness, and failure handling."""

from __future__ import annotations

import json

import pytest

from passman.core.backup.archive import (
    BackupCorruptError,
    BackupError,
    BackupWrongPassphraseError,
    backup_filename,
    create_backup,
    restore_backup,
    verify_backup,
)
from passman.core.crypto.kdf import Argon2Params
from passman.core.security.memory import SecretBytes
from passman.core.vaults.layout import VaultLayout

FAST = Argon2Params(time_cost=1, memory_cost_kib=8 * 1024, parallelism=1)


def _make_source_vault(fake_usb) -> VaultLayout:
    layout = VaultLayout.at(str(fake_usb), "ASH")
    layout.ensure_dirs()
    layout.kdbx_path.write_bytes(b"fake-kdbx-bytes")
    layout.keyfile_path.write_bytes(b"fake-keyfile-bytes")
    layout.vault_json.write_text(json.dumps({"vault_id": "v1", "name": "Test Vault"}))
    layout.devices_json.write_text(json.dumps([{"device_id": "d1", "label": "Laptop"}]))
    (layout.keyslots_dir / "password.slot").write_text('{"secret": "must-not-be-backed-up"}')
    (layout.keyslots_dir / "device-d1.slot").write_text('{"secret": "must-not-be-backed-up"}')
    return layout


def test_backup_filename_is_safe_and_stamped():
    name = backup_filename("My Passwords / Test")
    assert name.startswith("ash-backup-")
    assert name.endswith(".ashbak")
    assert "/" not in name


def test_create_and_restore_round_trip(fake_usb, tmp_path):
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("backup-passphrase"), params=FAST)

    restore_dir = tmp_path / "restored-usb"
    restore_dir.mkdir()
    destination = VaultLayout.at(str(restore_dir), "ASH")
    restore_backup(archive_path, destination, SecretBytes("backup-passphrase"))

    assert destination.kdbx_path.read_bytes() == b"fake-kdbx-bytes"
    assert destination.keyfile_path.read_bytes() == b"fake-keyfile-bytes"
    assert json.loads(destination.vault_json.read_text())["vault_id"] == "v1"
    assert json.loads(destination.devices_json.read_text())[0]["device_id"] == "d1"


def test_backup_excludes_key_slots(fake_usb, tmp_path):
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("backup-passphrase"), params=FAST)

    raw = archive_path.read_bytes()
    # The plaintext slot contents must never appear anywhere in the
    # encrypted archive bytes.
    assert b"must-not-be-backed-up" not in raw


def test_restore_wrong_passphrase_fails(fake_usb, tmp_path):
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("correct-passphrase"), params=FAST)

    restore_dir = tmp_path / "restored-usb"
    restore_dir.mkdir()
    destination = VaultLayout.at(str(restore_dir), "ASH")
    with pytest.raises(BackupWrongPassphraseError):
        restore_backup(archive_path, destination, SecretBytes("wrong-passphrase"))
    assert not destination.kdbx_path.exists()


def test_verify_backup_does_not_write_anything(fake_usb, tmp_path):
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("correct-passphrase"), params=FAST)

    assert verify_backup(archive_path, SecretBytes("correct-passphrase")) is True


def test_verify_backup_wrong_passphrase_raises(fake_usb, tmp_path):
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("correct-passphrase"), params=FAST)

    with pytest.raises(BackupWrongPassphraseError):
        verify_backup(archive_path, SecretBytes("wrong-passphrase"))


def test_create_backup_refuses_to_overwrite(fake_usb, tmp_path):
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("pw"), params=FAST)
    with pytest.raises(BackupError):
        create_backup(source, archive_path, SecretBytes("pw"), params=FAST)


def test_create_backup_fails_if_kdbx_missing(fake_usb, tmp_path):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    layout.ensure_dirs()
    layout.vault_json.write_text("{}")
    layout.devices_json.write_text("[]")
    with pytest.raises(BackupError):
        create_backup(layout, tmp_path / "backup.ashbak", SecretBytes("pw"), params=FAST)


def test_restore_refuses_nonempty_destination(fake_usb, tmp_path):
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("pw"), params=FAST)

    restore_dir = tmp_path / "restored-usb"
    restore_dir.mkdir()
    destination = VaultLayout.at(str(restore_dir), "ASH")
    destination.ensure_dirs()
    (destination.container_dir / "something.txt").write_text("pre-existing")

    with pytest.raises(BackupError):
        restore_backup(archive_path, destination, SecretBytes("pw"))


def test_corrupted_backup_file_raises_corrupt_error(tmp_path):
    archive_path = tmp_path / "backup.ashbak"
    archive_path.write_bytes(b"not a real backup file at all")
    destination = VaultLayout.at(str(tmp_path / "dest"), "ASH")
    with pytest.raises(BackupCorruptError):
        restore_backup(archive_path, destination, SecretBytes("pw"))


def test_truncated_backup_file_is_rejected(fake_usb, tmp_path):
    """A truncated file must never restore successfully. Whether it
    surfaces as BackupCorruptError (header itself cut short) or
    BackupWrongPassphraseError (header intact, ciphertext/tag no
    longer matches) depends on exactly where the cut lands -- both are
    the same AEAD-authentication-failure family, and deliberately
    indistinguishable from "wrong passphrase" (spec section 21)."""
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("pw"), params=FAST)

    truncated = tmp_path / "truncated.ashbak"
    full = archive_path.read_bytes()
    truncated.write_bytes(full[: len(full) // 2])

    destination = VaultLayout.at(str(tmp_path / "dest"), "ASH")
    with pytest.raises((BackupCorruptError, BackupWrongPassphraseError)):
        restore_backup(truncated, destination, SecretBytes("pw"))
    assert not destination.kdbx_path.exists()


def test_tampered_ciphertext_is_rejected(fake_usb, tmp_path):
    source = _make_source_vault(fake_usb)
    archive_path = tmp_path / "backup.ashbak"
    create_backup(source, archive_path, SecretBytes("pw"), params=FAST)

    raw = bytearray(archive_path.read_bytes())
    raw[-1] ^= 0xFF  # flip the last byte of the ciphertext
    archive_path.write_bytes(bytes(raw))

    destination = VaultLayout.at(str(tmp_path / "dest"), "ASH")
    with pytest.raises((BackupWrongPassphraseError, BackupCorruptError)):
        restore_backup(archive_path, destination, SecretBytes("pw"))
