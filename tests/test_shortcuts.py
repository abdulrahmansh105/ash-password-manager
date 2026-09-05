"""Tests for integration.shortcuts (spec section 9): accelerator
parsing, interface conformance, and the try-in-order fallback logic.
Uses hand-rolled fakes (this project's existing idiom) rather than a
live compositor/portal -- the live D-Bus wire-protocol correctness of
the portal backend was verified directly against this project's own
development machine during implementation (see portal.py's module
docstring for the exact, honestly-reported result)."""

from __future__ import annotations

from passman.integration.shortcuts.backend import BindOutcome, BindResult, ShortcutBackend
from passman.integration.shortcuts.gnome import GnomeShortcutBackend
from passman.integration.shortcuts.hyprland import HyprlandShortcutBackend, _accelerator_to_hyprland
from passman.integration.shortcuts.manual import ManualShortcutBackend
from passman.integration.shortcuts.portal import PortalShortcutBackend


def test_all_backends_conform_to_the_shared_interface():
    for cls in (PortalShortcutBackend, HyprlandShortcutBackend, GnomeShortcutBackend, ManualShortcutBackend):
        assert issubclass(cls, ShortcutBackend)
        instance = cls()
        assert isinstance(instance.name, str) and instance.name
        assert callable(instance.is_available)
        assert callable(instance.bind)


def test_accelerator_to_hyprland_simple_combo():
    assert _accelerator_to_hyprland("<Ctrl><Alt>p") == ("CTRL ALT", "P")


def test_accelerator_to_hyprland_single_modifier():
    assert _accelerator_to_hyprland("<Super>space") == ("SUPER", "SPACE")


def test_accelerator_to_hyprland_no_modifier_still_parses_key():
    assert _accelerator_to_hyprland("F12") == ("", "F12")


def test_accelerator_to_hyprland_unknown_modifier_returns_none():
    assert _accelerator_to_hyprland("<Hyper>p") is None


def test_accelerator_to_hyprland_empty_key_returns_none():
    assert _accelerator_to_hyprland("<Ctrl><Alt>") is None


def test_manual_backend_always_available_and_never_mutates_anything():
    backend = ManualShortcutBackend()
    assert backend.is_available() is True
    outcome = backend.bind("<Ctrl><Alt>p", "ash-password-manager show", "Open Manager")
    assert outcome.result == BindResult.UNAVAILABLE
    assert "<Ctrl><Alt>p" in outcome.detail


def test_hyprland_backend_bind_delegates_to_existing_keybind_module(monkeypatch):
    calls = []

    def fake_register_runtime_bind(exec_cmd, mods, key):
        calls.append((exec_cmd, mods, key))
        return True

    monkeypatch.setattr(
        "passman.integration.shortcuts.hyprland.keybind.register_runtime_bind", fake_register_runtime_bind
    )
    monkeypatch.setattr("passman.integration.shortcuts.hyprland.keybind.is_available", lambda: True)

    backend = HyprlandShortcutBackend()
    outcome = backend.bind("<Ctrl><Alt>p", "ash-password-manager show", "Open Manager")

    assert outcome.result == BindResult.OK
    assert calls == [("ash-password-manager show", "CTRL ALT", "P")]


def test_hyprland_backend_bind_fails_cleanly_when_hyprctl_fails(monkeypatch):
    monkeypatch.setattr("passman.integration.shortcuts.hyprland.keybind.register_runtime_bind", lambda *a, **k: False)
    monkeypatch.setattr("passman.integration.shortcuts.hyprland.keybind.is_available", lambda: True)

    backend = HyprlandShortcutBackend()
    outcome = backend.bind("<Ctrl><Alt>p", "ash-password-manager show", "Open Manager")
    assert outcome.result == BindResult.FAILED


def test_hyprland_backend_bind_fails_cleanly_on_unparseable_accelerator():
    backend = HyprlandShortcutBackend()
    outcome = backend.bind("<Hyper>p", "ash-password-manager show", "Open Manager")
    assert outcome.result == BindResult.FAILED


class _FakeBackend(ShortcutBackend):
    def __init__(self, name: str, available: bool, outcome: BindOutcome):
        self.name = name
        self._available = available
        self._outcome = outcome
        self.bind_calls: list[tuple[str, str, str]] = []

    def is_available(self) -> bool:
        return self._available

    def bind(self, accelerator: str, exec_cmd: str, description: str) -> BindOutcome:
        self.bind_calls.append((accelerator, exec_cmd, description))
        return self._outcome


def test_select_and_bind_stops_at_first_success(monkeypatch):
    from passman.integration import shortcuts as shortcuts_pkg

    first = _FakeBackend("first", True, BindOutcome(BindResult.FAILED))
    second = _FakeBackend("second", True, BindOutcome(BindResult.OK))
    third = _FakeBackend("third", True, BindOutcome(BindResult.OK))
    monkeypatch.setattr(shortcuts_pkg, "available_backends", lambda: [first, second, third])

    backend, outcome = shortcuts_pkg.select_and_bind("<Ctrl><Alt>p", "cmd", "desc")

    assert backend is second
    assert outcome.result == BindResult.OK
    assert first.bind_calls == [("<Ctrl><Alt>p", "cmd", "desc")]
    assert second.bind_calls == [("<Ctrl><Alt>p", "cmd", "desc")]
    assert third.bind_calls == []  # never reached -- stopped at the first success


def test_select_and_bind_falls_through_to_manual_when_all_fail(monkeypatch):
    from passman.integration import shortcuts as shortcuts_pkg

    only = _FakeBackend("only-fails", True, BindOutcome(BindResult.FAILED))
    manual = ManualShortcutBackend()
    monkeypatch.setattr(shortcuts_pkg, "available_backends", lambda: [only, manual])

    backend, outcome = shortcuts_pkg.select_and_bind("<Ctrl><Alt>p", "cmd", "desc")

    assert backend is manual
    assert outcome.result == BindResult.UNAVAILABLE


def test_select_and_bind_survives_a_backend_that_raises(monkeypatch):
    from passman.integration import shortcuts as shortcuts_pkg

    class _RaisingBackend(ShortcutBackend):
        name = "raises"

        def is_available(self) -> bool:
            return True

        def bind(self, accelerator: str, exec_cmd: str, description: str) -> BindOutcome:
            raise RuntimeError("simulated backend crash")

    fallback = _FakeBackend("fallback", True, BindOutcome(BindResult.OK))
    monkeypatch.setattr(shortcuts_pkg, "available_backends", lambda: [_RaisingBackend(), fallback])

    backend, outcome = shortcuts_pkg.select_and_bind("<Ctrl><Alt>p", "cmd", "desc")
    assert backend is fallback
    assert outcome.result == BindResult.OK


def test_select_and_bind_falls_through_when_hyprland_registration_actually_fails(monkeypatch):
    """Regression for the exact bug: HyprlandShortcutBackend.bind()
    must genuinely propagate a registration failure (not swallow it
    behind a lying exit code) so select_and_bind's existing fallback
    chain moves on to the next backend -- exercised through the real
    HyprlandShortcutBackend.bind(), not a _FakeBackend stand-in."""
    from passman.integration import shortcuts as shortcuts_pkg

    monkeypatch.setattr("passman.integration.shortcuts.hyprland.keybind.is_available", lambda: True)
    monkeypatch.setattr("passman.integration.shortcuts.hyprland.keybind.register_runtime_bind", lambda *a, **k: False)

    hyprland = HyprlandShortcutBackend()
    manual = ManualShortcutBackend()
    monkeypatch.setattr(shortcuts_pkg, "available_backends", lambda: [hyprland, manual])

    backend, outcome = shortcuts_pkg.select_and_bind("<Ctrl><Alt>p", "ash-password-manager sign-in", "Open Manager")

    assert backend is manual
    assert outcome.result == BindResult.UNAVAILABLE


def test_available_backends_always_ends_with_manual():
    from passman.integration.shortcuts import available_backends

    backends = available_backends()
    assert backends[-1].name == "manual"
    assert isinstance(backends[-1], ManualShortcutBackend)
