"""Regression tests for bug fix #1 (spec sections 1, 9, 27): the
configured global hotkey must target the new multi-vault sign-in/login
entry point, never the legacy single-vault `show` command. Live,
real-Hyprland end-to-end verification of this exact fix is also
covered separately (not part of the automated suite, which never
touches the real compositor); these are the fast, always-run
regressions that would catch the exec-command target silently
reverting."""

from __future__ import annotations


def test_setup_wizard_hotkey_targets_new_sign_in_flow():
    from passman.ui.setup import setup_window

    assert setup_window._HOTKEY_EXEC_CMD == "ash-password-manager sign-in"
    assert "show" not in setup_window._HOTKEY_EXEC_CMD


def test_settings_hotkey_targets_new_sign_in_flow():
    from passman.ui import settings_window

    assert settings_window._HOTKEY_EXEC_CMD == "ash-password-manager sign-in"
    assert "show" not in settings_window._HOTKEY_EXEC_CMD


def test_agent_reapplies_hotkey_to_the_new_sign_in_flow(monkeypatch):
    """The background agent re-applies the configured hotkey at every
    startup (for backends like Hyprland whose runtime bind does not
    survive a compositor restart) -- it must reapply the same,
    corrected exec command, not the legacy one it used to hardcode."""
    from passman.config.store import Settings
    from passman.launcher.agent import UsbWatchAgent

    calls = []

    class FakeBackend:
        name = "hyprland"

        def reapply_on_startup(self, accelerator, exec_cmd, description):
            calls.append((accelerator, exec_cmd, description))

    fake_settings = Settings(hotkey_accelerator="<Control><Alt>p", hotkey_backend="hyprland")
    monkeypatch.setattr("passman.config.store.load_settings", lambda: fake_settings)
    monkeypatch.setattr("passman.integration.shortcuts.available_backends", lambda: [FakeBackend()])

    UsbWatchAgent()._reapply_hotkey()

    assert len(calls) == 1
    accelerator, exec_cmd, _description = calls[0]
    assert accelerator == "<Control><Alt>p"
    assert exec_cmd == "ash-password-manager sign-in"


def test_agent_does_not_reapply_when_no_hotkey_configured_yet(monkeypatch):
    from passman.config.store import Settings
    from passman.launcher.agent import UsbWatchAgent

    calls = []

    class FakeBackend:
        name = "hyprland"

        def reapply_on_startup(self, accelerator, exec_cmd, description):
            calls.append((accelerator, exec_cmd, description))

    fake_settings = Settings(hotkey_accelerator="", hotkey_backend="")
    monkeypatch.setattr("passman.config.store.load_settings", lambda: fake_settings)
    monkeypatch.setattr("passman.integration.shortcuts.available_backends", lambda: [FakeBackend()])

    UsbWatchAgent()._reapply_hotkey()

    assert calls == []
