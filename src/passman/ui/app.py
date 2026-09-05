"""GTK4 + Libadwaita application entry point for the main (unlocked)
password manager UI. Same framework choice/rationale as
password-template-generator (see that project's gui/app.py) -- native,
Wayland-first, and DMS-themed for free via named GTK colors.

This process becomes the "one running UI instance" that the launcher
(``launcher.daemon``) checks for via the control socket
(``launcher.ipc``). It owns the unlocked ``Session`` and is the only
place in the whole application where vault secrets are ever held in
memory.
"""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from ..config.store import Settings, UsbRegistration, load_settings  # noqa: E402
from ..core.auth.detection import DetectedContext  # noqa: E402
from ..core.security.logging import get_logger, safe_extra  # noqa: E402
from ..core.security.session import LockReason, Session  # noqa: E402
from ..core.vault.kdbx import VaultOpenError, open_vault  # noqa: E402
from ..integration.logind import LogindWatcher  # noqa: E402
from ..integration import notify  # noqa: E402
from ..integration.usb.identity import evaluate_usb_status, should_lock_for_usb_removal  # noqa: E402
from ..integration.usb.udisks import UdisksError, list_block_devices  # noqa: E402
from ..launcher.ipc import ControlServer, status_json  # noqa: E402
from .launcher_window import AccountPickerWindow  # noqa: E402
from .locked_window import LockedWindow  # noqa: E402

APP_ID = "dev.ash.PasswordManager"
_log = get_logger(__name__)

_LOCK_REASON_MESSAGES = {
    LockReason.USB_REMOVED: "The vault's USB was removed.",
    LockReason.SCREEN_LOCKED: "The screen was locked.",
    LockReason.SUSPENDED: "The system suspended.",
    LockReason.INACTIVITY_TIMEOUT: "Locked after a period of inactivity.",
    LockReason.MANUAL_CLOSE: "Locked manually.",
    LockReason.VAULT_ERROR: "Locked due to a vault error.",
    LockReason.STARTUP: "Locked at startup.",
}


def _notify_lock_reason(reason: LockReason) -> None:
    """Best-effort desktop notification only (spec section 20) --
    never a substitute for the actual lock, which has already
    happened by the time this runs. Never includes any secret; only
    the fixed, non-secret reason label above."""
    notify.notify_vault_locked(_LOCK_REASON_MESSAGES.get(reason, "The vault was locked."))


class PasswordManagerApp(Adw.Application):
    def __init__(
        self,
        mountpoint: str,
        registration: UsbRegistration,
        detected_context: DetectedContext | None = None,
        *,
        unlocked_vault: object | None = None,
    ) -> None:
        """``registration`` is duck-typed: either the legacy
        ``UsbRegistration`` (keyfile-only vaults, the original flow)
        or a ``core.vaults.registry.VaultRecord`` (the new multi-vault
        model) -- both expose ``.luks_uuid``/``.filesystem_uuid``,
        which is all this class and ``_check_usb_still_present`` ever
        read off it directly.

        ``unlocked_vault``, when given, is an already-open
        ``core.vault.kdbx.VaultHandle`` obtained through the new login
        flow (``core.flows.login_machine`` + ``core.devices.registry``
        -- Local Key or master password, see ``ui.login``). Passing it
        skips the legacy keyfile-only ``open_vault(..., password=None)``
        path entirely; every other subsystem here (control server,
        logind watcher, inactivity/USB-removal ticking, lock/teardown)
        is unchanged and reused as-is for both flows.
        """
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.mountpoint = mountpoint
        self.registration = registration
        self.vault_id: str | None = getattr(registration, "vault_id", None)
        self._unlocked_vault = unlocked_vault
        # Legacy flow (no unlocked_vault given) keeps opening the
        # original autotype-focused picker, byte-for-byte unchanged.
        # The new login flow (ui.login) always supplies
        # unlocked_vault, which is also the signal to open the new
        # Manager instead (spec section 23) -- autotype remains one
        # click away from there (entry detail view / Settings ->
        # Authentication), never the default interaction (spec
        # section 34 decision).
        self._window_cls = AccountPickerWindow
        if unlocked_vault is not None:
            from .manager.main_window import ManagerWindow

            self._window_cls = ManagerWindow
        # Captured once by launcher.daemon.run_show() *before* this
        # window ever took focus -- see that module's docstring. Never
        # re-queried later, or it would only ever see this app's own
        # window.
        self.detected_context = detected_context or DetectedContext(app_id=None, window_title=None)
        self.settings: Settings = load_settings()
        self.session = Session(inactivity_timeout_seconds=self.settings.effective_auto_lock_timeout_seconds())
        self.session.set_on_lock(self._on_session_locked)
        self._window: AccountPickerWindow | None = None
        self._control: ControlServer | None = None
        self._logind_watcher: LogindWatcher | None = None
        self._ash_theme_provider = None
        self._install_actions()

    def _install_actions(self) -> None:
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self._manual_close())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Control>q"])

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        self._load_css()
        self._apply_theme()
        self._apply_brand_theme()
        self._disable_animations()
        self._open_vault_or_fail()
        self._start_control_server()
        self._start_logind_watcher()
        # 2s: fast enough that USB removal reads as "immediate" to a
        # human, without a tight busy-loop. USB-presence and inactivity
        # are both checked every tick (see _tick()).
        GLib.timeout_add_seconds(2, self._tick)

    def _start_logind_watcher(self) -> None:
        if not (self.settings.lock_on_screen_lock or self.settings.lock_on_suspend):
            return
        watcher = LogindWatcher(
            on_sleep=self._on_logind_sleep,
            on_screen_locked=self._on_logind_screen_locked,
        )
        if watcher.start():
            self._logind_watcher = watcher

    def _on_logind_sleep(self) -> None:
        if self.settings.lock_on_suspend:
            GLib.idle_add(lambda: (self.session.lock(LockReason.SUSPENDED), False)[1])

    def _on_logind_screen_locked(self) -> None:
        if self.settings.lock_on_screen_lock:
            GLib.idle_add(lambda: (self.session.lock(LockReason.SCREEN_LOCKED), False)[1])

    def _disable_animations(self) -> None:
        # Spec requirement: no animations anywhere in this app. GTK4's
        # single global switch covers built-in transitions (Adw.Banner
        # reveal, Adw.ViewStack page switches, Gtk.Revealer, etc.)
        # without having to zero out `transition-type` on every widget
        # individually.
        settings = Gtk.Settings.get_default()
        if settings is not None:
            settings.set_property("gtk-enable-animations", False)

    def do_activate(self) -> None:
        if self._window is None:
            self._window = self._window_cls(self)
        self._window.present()

    def _apply_theme(self) -> None:
        # "dms" (default) = Adw.ColorScheme.DEFAULT, which already
        # follows the system/DMS light-dark preference; explicit
        # dark/light are provided as an override for users who want one
        # regardless of DMS's current setting.
        mapping = {
            "dms": Adw.ColorScheme.DEFAULT,
            "dark": Adw.ColorScheme.FORCE_DARK,
            "light": Adw.ColorScheme.FORCE_LIGHT,
        }
        Adw.StyleManager.get_default().set_color_scheme(mapping.get(self.settings.theme, Adw.ColorScheme.DEFAULT))

    def _apply_brand_theme(self) -> None:
        """The "ash" theme (spec section 22's white/blue/clean brand
        identity, and the default for new installs) layers a second,
        static CSS provider on top of the DMS-following behavior
        ``_apply_theme()`` already implements -- see ``ui/theme.py``'s
        docstring for exactly how this coexists with DMS's live
        ~/.config/gtk-4.0/gtk.css instead of fighting it. Any other
        theme choice ("dms"/"dark"/"light") leaves this a no-op,
        preserving the original "never hardcode a color" behavior
        exactly."""
        if self.settings.theme != "ash":
            return
        from .theme import apply_ash_theme

        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
        self._ash_theme_provider = apply_ash_theme()

    def _load_css(self) -> None:
        provider = Gtk.CssProvider()
        css_path = Path(__file__).with_name("style.css")
        provider.load_from_path(str(css_path))
        display = Gdk.Display.get_default()
        if display is not None:
            Gtk.StyleContext.add_provider_for_display(
                display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    def _open_vault_or_fail(self) -> None:
        if self._unlocked_vault is not None:
            # New flow: core.flows.login_machine + core.devices.registry
            # already authenticated (Local Key or master password) and
            # opened this handle -- see ui.login. Nothing left to do but
            # hand it to the session.
            handle, self._unlocked_vault = self._unlocked_vault, None
            self.session.unlock(handle)
            return
        # Legacy flow: keyfile-only vault, no master password (the
        # original design this application shipped with). Unchanged.
        vault_path = Path(self.mountpoint) / self.registration.vault_rel_path
        key_path = Path(self.mountpoint) / self.registration.keyfile_rel_path
        try:
            handle = open_vault(vault_path, key_path, password=None)
        except VaultOpenError as exc:
            _log.warning("vault open failed", extra=safe_extra(event="vault_open_failed", cause=type(exc).__name__))
            LockedWindow(self, reason="Could not open the vault on this USB.").present()
            return
        self.session.unlock(handle)

    def _start_control_server(self) -> None:
        handlers = {
            "ping": lambda _c: "pong",
            "lock": self._handle_lock_command,
            "focus": self._handle_focus_command,
            "status": self._handle_status_command,
        }
        self._control = ControlServer(handlers)
        self._control.start()

    def _handle_lock_command(self, _cmd: str) -> str:
        GLib.idle_add(self._manual_lock_from_ipc)
        return "ok"

    def _manual_lock_from_ipc(self) -> bool:
        self.session.lock(LockReason.INACTIVITY_TIMEOUT)
        return False

    def _handle_focus_command(self, _cmd: str) -> str:
        GLib.idle_add(self._present_window)
        return "ok"

    def _present_window(self) -> bool:
        if self._window is not None:
            self._window.present()
        return False

    def _handle_status_command(self, _cmd: str) -> str:
        return status_json(state=self.session.state.value, mountpoint=self.mountpoint)

    def _tick(self) -> bool:
        if not self.session.is_unlocked():
            return False  # already locked/torn down; stop polling
        self.session.check_inactivity()
        if self.settings.lock_on_usb_removal:
            self._check_usb_still_present()
        return True  # keep the periodic check running

    def _check_usb_still_present(self) -> None:
        """USB removal -> lock, gated by the user's configured removal
        policy (spec sections 8, 10, 33, 34). The actual pass/fail
        decision is the pure, independently unit-tested
        ``should_lock_for_usb_removal`` (see tests/test_usb_identity.py
        and tests/test_usb_removal_policy.py) -- this method only does
        the real device query and passes its result through.

        The query-failure branch below is deliberately NOT gated by
        ``usb_removal_action``: it fires when the USB's status could
        not even be determined (e.g. UDisks2 itself is unreachable),
        which is a different, rarer condition than "the USB was
        removed" -- fail-closed there regardless of the removal
        policy, since "keep unlocked on removal" is a statement about
        a *confirmed* removal, not about being unable to verify the
        vault's security boundary at all."""
        try:
            devices = list_block_devices()
            status = evaluate_usb_status(devices, self.registration)
        except UdisksError:
            self.session.lock(LockReason.USB_REMOVED)
            return
        if should_lock_for_usb_removal(status, self.mountpoint, self.settings.usb_removal_action):
            self.session.lock(LockReason.USB_REMOVED)

    def _on_session_locked(self, reason: LockReason) -> None:
        _log.info("locking UI", extra=safe_extra(event="ui_lock", reason=reason.value))
        _notify_lock_reason(reason)
        GLib.idle_add(self._teardown_after_lock)

    def _teardown_after_lock(self) -> bool:
        if self._window is not None:
            self._window.destroy_sensitive_state()
            self._window.close()
            self._window = None
        if self._control is not None:
            self._control.stop()
            self._control = None
        if self._logind_watcher is not None:
            self._logind_watcher.stop()
            self._logind_watcher = None
        self.quit()
        return False

    def _manual_close(self) -> None:
        self.session.lock(LockReason.MANUAL_CLOSE)


def run_main_app(
    mountpoint: str,
    registration: UsbRegistration,
    detected_context: DetectedContext | None = None,
    *,
    unlocked_vault: object | None = None,
) -> int:
    app = PasswordManagerApp(mountpoint, registration, detected_context, unlocked_vault=unlocked_vault)
    return app.run(None)


def run_setup_window() -> int:
    """No vault USB registered yet. Rather than a bespoke GTK wizard
    (the fully-interactive USB registration flow is significant extra
    surface with real risk of getting device selection subtly wrong --
    this project intentionally keeps that step on the more easily
    auditable/scriptable `password-manager setup` CLI, spec section 20's
    "USB / Vault ... re-register USB" is served by that command), show a
    minimal pointer window."""
    app = Adw.Application(application_id=f"{APP_ID}.Setup", flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def on_activate(a: Adw.Application) -> None:
        window = Adw.Window(application=a, title="Password Manager", default_width=420, default_height=200)
        status = Adw.StatusPage(
            title="No vault registered",
            description="Run `password-manager setup` in a terminal to register your vault USB.",
            icon_name="dialog-password-symbolic",
        )
        window.set_content(status)
        window.present()

    app.connect("activate", on_activate)
    return app.run(None)
