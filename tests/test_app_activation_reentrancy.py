"""Regression tests: a second GApplication "activate" (fired again for
every activation, including one relayed over D-Bus from a separate
process invocation while this one is already running -- confirmed
live: re-running `ash-password-manager sign-in` while the Setup wizard
was already open silently created a second, independent window on the
same process, with the CLI invocation itself returning immediately,
giving no visible feedback that anything happened) must focus the
existing window, never construct a duplicate.

Substitutes a lightweight real Gtk.Window subclass for the real
Setup/Login/Locked window classes (module-level monkeypatch -- do_activate
resolves that name dynamically from its own module's namespace at call
time, so this is picked up correctly) so these tests never construct
the real, much heavier windows (which would also enumerate real USB
drives) and never visibly flash the actual wizard on screen.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk  # noqa: E402


class _FakeSetupWindow(Gtk.Window):
    def __init__(self, app) -> None:
        super().__init__(application=app)
        self.result_handle = None
        self.result_record = None
        self.discovered_existing_vault = None
        self._mountpoint = None


class _FakeLoginWindow(Gtk.Window):
    def __init__(self, app, record, mountpoint) -> None:
        super().__init__(application=app)
        self.result_handle = None


class _FakeLockedWindow(Gtk.Window):
    def __init__(self, app, reason: str) -> None:
        super().__init__(application=app)
        self.reason = reason


def test_setup_app_do_activate_is_idempotent(monkeypatch):
    import passman.ui.setup.setup_window as setup_window_mod

    monkeypatch.setattr(setup_window_mod, "SetupWindow", _FakeSetupWindow)

    app = setup_window_mod.SetupApp()
    app.do_activate()
    first_window = app._window
    assert first_window is not None

    present_calls = []
    monkeypatch.setattr(first_window, "present", lambda: present_calls.append(1))

    app.do_activate()

    assert app._window is first_window, "a second activate must not replace the existing window"
    assert present_calls == [1], "a second activate must (re-)present the existing window"
    first_window.close()


def test_login_app_do_activate_is_idempotent(monkeypatch):
    import passman.ui.login.login_window as login_window_mod
    from passman.core.vaults.registry import VaultRecord

    monkeypatch.setattr(login_window_mod, "LoginWindow", _FakeLoginWindow)
    record = VaultRecord(vault_id="v1", name="Test", filesystem_uuid="fs-1")

    app = login_window_mod.LoginApp(record, "/mnt/vault")
    app.do_activate()
    first_window = app._window
    assert first_window is not None

    present_calls = []
    monkeypatch.setattr(first_window, "present", lambda: present_calls.append(1))

    app.do_activate()

    assert app._window is first_window
    assert present_calls == [1]
    first_window.close()


def test_show_locked_window_activate_is_idempotent(monkeypatch):
    """Exercises the real show_locked_window() function itself (not a
    re-implementation of its closure) -- Adw.Application.run() is
    patched to call .activate() twice and return immediately instead
    of blocking in a real main loop, since this function's own return
    value is app.run(None)."""
    import passman.ui.locked_window as locked_window_mod

    monkeypatch.setattr(locked_window_mod, "LockedWindow", _FakeLockedWindow)

    constructed: list = []
    orig_new_window_init = _FakeLockedWindow.__init__

    def counting_init(self, app, reason):
        constructed.append(self)
        orig_new_window_init(self, app, reason)

    monkeypatch.setattr(_FakeLockedWindow, "__init__", counting_init)

    from gi.repository import Adw

    def fake_run(self, _argv):
        self.register()  # real run() does this internally before the first activate
        self.activate()
        self.activate()  # simulates a second, D-Bus-relayed activation
        return 0

    monkeypatch.setattr(Adw.Application, "run", fake_run)

    code = locked_window_mod.show_locked_window("test reason")

    assert code == 0
    assert len(constructed) == 1, f"a second activate must not construct a duplicate LockedWindow, got {len(constructed)}"
    constructed[0].close()
