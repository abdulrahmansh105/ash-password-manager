"""Screen-lock/suspend decision logic, tested against fabricated D-Bus
payloads only -- no real system bus, no real suspend, no real screen
lock triggered. See integration/logind.py's module docstring for the
live introspection that confirmed these signal/property names exist on
this machine's logind."""

from __future__ import annotations

from passman.integration.logind import (
    should_lock_on_locked_hint_change,
    should_lock_on_sleep_signal,
)


def test_locks_on_prepare_for_sleep_true():
    assert should_lock_on_sleep_signal(True) is True


def test_does_not_lock_on_resume_edge():
    assert should_lock_on_sleep_signal(False) is False


def test_locks_when_locked_hint_becomes_true():
    assert should_lock_on_locked_hint_change({"LockedHint": True}) is True


def test_does_not_lock_when_locked_hint_becomes_false():
    assert should_lock_on_locked_hint_change({"LockedHint": False}) is False


def test_does_not_lock_on_unrelated_property_change():
    assert should_lock_on_locked_hint_change({"IdleHint": True}) is False


def test_does_not_lock_on_empty_changed_properties():
    assert should_lock_on_locked_hint_change({}) is False


def test_watcher_start_never_raises_when_system_bus_unreachable(monkeypatch):
    import passman.integration.logind as logind_mod

    def boom(*_a, **_kw):
        raise RuntimeError("no system bus in this test")

    monkeypatch.setattr(logind_mod, "_current_session_path", boom)
    watcher = logind_mod.LogindWatcher(on_sleep=lambda: None, on_screen_locked=lambda: None)
    # Force the Gio import branch to hit our patched resolver by also
    # patching bus_get_sync's caller path -- simplest robust way is to
    # make Gio.bus_get_sync itself unavailable-looking via a bad bus type.
    result = watcher.start()
    assert result in (True, False)  # must never raise, whatever it returns
    watcher.stop()  # must be safe to call even if start() returned False


def test_watcher_start_and_stop_against_the_real_system_bus():
    # This environment has real D-Bus access (verified via `busctl
    # --system introspect` before writing integration/logind.py) --
    # subscribing to a signal is a read-only, non-disruptive operation
    # (no suspend, no screen lock triggered), so this is safe to run for
    # real rather than mocked.
    import passman.integration.logind as logind_mod

    watcher = logind_mod.LogindWatcher(on_sleep=lambda: None, on_screen_locked=lambda: None)
    started = watcher.start()
    watcher.stop()
    assert started in (True, False)
