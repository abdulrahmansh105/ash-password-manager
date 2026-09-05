from __future__ import annotations

import stat

import pytest

from passman.config import store


@pytest.fixture(autouse=True)
def isolated_config_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    yield tmp_path


def test_load_settings_defaults_when_missing():
    s = store.load_settings()
    assert s.safety_guard_mode == "auto_high_confidence"
    assert s.clipboard_fallback_enabled is False


def test_save_and_reload_settings_round_trip():
    s = store.load_settings()
    s.inactivity_timeout_seconds = 42
    s.clipboard_fallback_enabled = True
    store.save_settings(s)

    reloaded = store.load_settings()
    assert reloaded.inactivity_timeout_seconds == 42
    assert reloaded.clipboard_fallback_enabled is True


def test_settings_file_permissions_are_restrictive():
    store.save_settings(store.load_settings())
    path = store.config_dir() / "settings.json"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_config_dir_permissions_are_restrictive():
    store.save_settings(store.load_settings())
    mode = stat.S_IMODE(store.config_dir().stat().st_mode)
    assert mode == 0o700


def test_corrupt_settings_file_falls_back_to_defaults(tmp_path):
    store._ensure_config_dir()
    (store.config_dir() / "settings.json").write_text("{not valid json", encoding="utf-8")
    s = store.load_settings()
    assert s.safety_guard_mode == "auto_high_confidence"


def test_usb_registration_round_trip():
    reg = store.UsbRegistration(luks_uuid="11111111-1111-1111-1111-111111111111", filesystem_uuid="ffffffff-ffff-ffff-ffff-ffffffffffff")
    store.save_usb_registration(reg)
    loaded = store.load_usb_registration()
    assert loaded is not None
    assert loaded.luks_uuid == reg.luks_uuid
    assert loaded.filesystem_uuid == reg.filesystem_uuid


def test_no_usb_registration_returns_none():
    assert store.load_usb_registration() is None


def test_clear_usb_registration():
    reg = store.UsbRegistration(luks_uuid="x", filesystem_uuid="y")
    store.save_usb_registration(reg)
    store.clear_usb_registration()
    assert store.load_usb_registration() is None


def test_invalid_theme_falls_back():
    store._atomic_write_json(store.config_dir() / "settings.json", {"theme": "not-a-theme"})
    s = store.load_settings()
    assert s.theme == "ash"


def test_invalid_safety_guard_mode_falls_back():
    store._atomic_write_json(store.config_dir() / "settings.json", {"safety_guard_mode": "bogus"})
    s = store.load_settings()
    assert s.safety_guard_mode == "auto_high_confidence"


def test_invalid_usb_removal_action_falls_back():
    store._atomic_write_json(store.config_dir() / "settings.json", {"usb_removal_action": "bogus"})
    s = store.load_settings()
    assert s.usb_removal_action == "lock_immediately"


def test_usb_removal_action_persists_lock_immediately_across_a_simulated_restart():
    # A fresh load_settings() call re-reads from disk with no
    # in-memory cache anywhere in this module -- this genuinely
    # exercises "does the choice survive a restart", not just
    # "does the in-memory dataclass field hold its value".
    s = store.load_settings()
    s.usb_removal_action = "lock_immediately"
    store.save_settings(s)

    reloaded = store.load_settings()
    assert reloaded.usb_removal_action == "lock_immediately"


def test_usb_removal_action_persists_keep_unlocked_across_a_simulated_restart():
    s = store.load_settings()
    s.usb_removal_action = "keep_unlocked"
    store.save_settings(s)

    reloaded = store.load_settings()
    assert reloaded.usb_removal_action == "keep_unlocked"


def test_usb_removal_action_switching_back_and_forth_persists_the_latest_choice():
    s = store.load_settings()
    s.usb_removal_action = "keep_unlocked"
    store.save_settings(s)
    assert store.load_settings().usb_removal_action == "keep_unlocked"

    s2 = store.load_settings()
    s2.usb_removal_action = "lock_immediately"
    store.save_settings(s2)
    assert store.load_settings().usb_removal_action == "lock_immediately"
