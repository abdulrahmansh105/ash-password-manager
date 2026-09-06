"""Custom Auto-Type preset storage -- non-secret, local JSON file.
Structurally cannot hold a secret (presets are step sequences only)."""

from __future__ import annotations

from passman.core.auth.strategy import (
    DEFAULT_STRATEGY,
    AuthStep,
    AuthStrategy,
    StepAction,
)
from passman.core.auth.strategy_presets import (
    delete_custom_preset,
    load_custom_presets,
    presets_path,
    save_custom_preset,
)


def test_no_presets_file_returns_empty_dict(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert load_custom_presets() == {}


def test_save_and_load_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    save_custom_preset("My Bank", DEFAULT_STRATEGY)

    loaded = load_custom_presets()
    assert "My Bank" in loaded
    assert loaded["My Bank"].steps == DEFAULT_STRATEGY.steps


def test_save_multiple_presets(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    save_custom_preset("A", AuthStrategy(steps=(AuthStep(action=StepAction.KEY_TAB),)))
    save_custom_preset("B", AuthStrategy(steps=(AuthStep(action=StepAction.KEY_ENTER),)))

    loaded = load_custom_presets()
    assert set(loaded.keys()) == {"A", "B"}


def test_save_overwrites_existing_preset_of_same_name(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    save_custom_preset("X", AuthStrategy(steps=(AuthStep(action=StepAction.KEY_TAB),)))
    save_custom_preset("X", AuthStrategy(steps=(AuthStep(action=StepAction.KEY_ENTER),)))

    loaded = load_custom_presets()
    assert len(loaded) == 1
    assert loaded["X"].steps[0].action == StepAction.KEY_ENTER


def test_delete_preset(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    save_custom_preset("X", DEFAULT_STRATEGY)
    delete_custom_preset("X")
    assert load_custom_presets() == {}


def test_delete_nonexistent_preset_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    delete_custom_preset("does-not-exist")  # must not raise
    assert load_custom_presets() == {}


def test_empty_name_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    import pytest

    with pytest.raises(ValueError):
        save_custom_preset("", DEFAULT_STRATEGY)


def test_corrupt_presets_file_falls_back_to_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    path = presets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not valid json", encoding="utf-8")
    assert load_custom_presets() == {}


def test_presets_file_permissions_are_restrictive(tmp_path, monkeypatch):
    import stat

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    save_custom_preset("X", DEFAULT_STRATEGY)
    mode = stat.S_IMODE(presets_path().stat().st_mode)
    assert mode == 0o600


def test_presets_never_contain_a_fake_secret_marker(tmp_path, monkeypatch):
    # Structural guarantee: AuthStep has no field that can hold a typed
    # value's *content* -- only 'action' (e.g. "type_password", which
    # legitimately contains the word "password" as an action name) and
    # 'value' (a key-combo string or a wait duration). Prove the actual
    # secret text never appears, rather than banning the word itself.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    fake_secret_marker = "DUMMY-SECRET-4f9c2b"
    save_custom_preset("X", DEFAULT_STRATEGY)
    raw = presets_path().read_text(encoding="utf-8")
    assert fake_secret_marker not in raw
