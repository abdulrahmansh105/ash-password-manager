"""Tests for core.vaults.health -- the integrity manifest and vault
health-check report (spec sections 21, 24, 25)."""

from __future__ import annotations

from passman.core.vaults.health import (
    HealthStatus,
    check_vault_health,
    update_integrity_manifest,
)
from passman.core.vaults.layout import VaultLayout


def _minimal_vault(layout: VaultLayout) -> None:
    layout.ensure_dirs()
    layout.vault_json.write_text('{"vault_id": "x"}')
    layout.kdbx_path.write_bytes(b"fake-kdbx-bytes")
    layout.keyfile_path.write_bytes(b"fake-keyfile-bytes")
    layout.devices_json.write_text("[]")
    (layout.keyslots_dir / "password.slot").write_text("{}")


def test_health_report_all_ok_for_a_complete_vault(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    _minimal_vault(layout)
    update_integrity_manifest(layout)
    report = check_vault_health(layout)
    assert report.status == HealthStatus.OK


def test_health_report_error_when_kdbx_missing(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    layout.ensure_dirs()
    layout.vault_json.write_text("{}")
    report = check_vault_health(layout)
    assert report.status == HealthStatus.ERROR
    assert any("Passwords.kdbx" in c.name and c.status == HealthStatus.ERROR for c in report.checks)


def test_health_report_error_when_password_slot_missing(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    _minimal_vault(layout)
    (layout.keyslots_dir / "password.slot").unlink()
    report = check_vault_health(layout)
    assert report.status == HealthStatus.ERROR


def test_health_report_warning_when_no_manifest_yet(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    _minimal_vault(layout)
    report = check_vault_health(layout)
    assert report.status == HealthStatus.WARNING


def test_health_report_warning_when_devices_json_changed_after_manifest(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    _minimal_vault(layout)
    update_integrity_manifest(layout)
    layout.devices_json.write_text('[{"tampered": true}]')
    report = check_vault_health(layout)
    assert report.status == HealthStatus.WARNING
    assert any("Integrity manifest" in c.name for c in report.checks)


def test_manifest_counts_device_slots(fake_usb):
    layout = VaultLayout.at(str(fake_usb), "ASH")
    _minimal_vault(layout)
    (layout.keyslots_dir / "device-abc.slot").write_text("{}")
    report = check_vault_health(layout)
    device_check = next(c for c in report.checks if c.name == "Device slots")
    assert "1 registered device" in device_check.detail
