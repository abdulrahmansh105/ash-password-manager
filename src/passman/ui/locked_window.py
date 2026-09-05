"""The USB-absent / locked-state popup (spec sections 3, 25).

Deliberately minimal: it is constructed *before* any vault has been
opened, so it is structurally incapable of showing vault data -- there
is no vault handle in scope anywhere in this module.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio  # noqa: E402

APP_ID = "dev.ash.PasswordManager.Locked"


def show_locked_window(reason: str) -> int:
    app = Adw.Application(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
    window_box: list[LockedWindow] = []

    def on_activate(a: Adw.Application) -> None:
        # Same re-entrancy guard as SetupApp/LoginApp/PasswordManagerApp
        # -- a second "activate" relayed over D-Bus while this window
        # is already open must focus it, never create a duplicate.
        if not window_box:
            window_box.append(LockedWindow(a, reason=reason))
        window_box[0].present()

    app.connect("activate", on_activate)
    return app.run(None)


class LockedWindow(Adw.Window):
    def __init__(self, application: Adw.Application, reason: str) -> None:
        super().__init__(application=application, default_width=380, default_height=220, modal=False)

        # Adw.Window has no set_titlebar() (unlike plain Gtk.Window) --
        # confirmed live: calling it is a fatal
        # "gtk_window_set_titlebar() is not supported for AdwWindow"
        # Adwaita error that crashed this window's process outright.
        # Adw.ToolbarView is the supported way to combine a header bar
        # with content in a plain Adw.Window (AccountPickerWindow and
        # every dialog in this app already use this correctly; this was
        # the one holdout using the wrong API).
        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar(show_title=False))

        status = Adw.StatusPage(
            title="Password Manager is locked",
            description=reason or "Insert your USB key to continue.",
            icon_name="channel-secure-symbolic",
        )
        toolbar_view.set_content(status)
        self.set_content(toolbar_view)

        key_controller = self._make_escape_controller()
        self.add_controller(key_controller)

    def _make_escape_controller(self):
        from gi.repository import Gdk, Gtk

        controller = Gtk.EventControllerKey()

        def on_key(_c, keyval, _keycode, _state):
            if keyval == Gdk.KEY_Escape:
                self.close()
                return True
            return False

        controller.connect("key-pressed", on_key)
        return controller
