"""Login popup shown when a registered ASH vault USB is connected
(spec sections 1, 8, 27).

The hard product rule (spec section 1): if a valid Local Key exists
for this device, the password is never requested. This window's
"checking" page always runs first, silently and automatically; the
password page only ever appears once
``core.flows.login_machine.attempt_automatic_login`` has already
concluded that no valid Local Key is available -- there is no code
path in this file that shows the password page before that check has
run, and none that returns to the Local Key check afterwards (so a
login can never loop, matching ``LoginFlow``'s own guarantee).

All crypto/file I/O (Argon2id, AES-GCM, reading the Local Key/slots)
runs on a background thread via the existing
``core.auth.async_login.run_blocking_async`` helper -- it is entirely
generic despite living in ``core.auth``, and reusing it here avoids
freezing the GTK main loop during a master-password unlock exactly the
way it already prevents that during autotype.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from ...core.auth.async_login import run_blocking_async  # noqa: E402
from ...core.crypto.keyslots import vms_to_kdbx_password  # noqa: E402
from ...core.devices import local_key as local_key_store  # noqa: E402
from ...core.devices import registry as device_registry  # noqa: E402
from ...core.flows.login_machine import (  # noqa: E402
    LoginFailureReason,
    LoginFlow,
    LoginOutcome,
    LoginState,
    attempt_automatic_login,
)
from ...core.platforminfo import default_device_label  # noqa: E402
from ...core.security.logging import get_logger, safe_extra  # noqa: E402
from ...integration import notify  # noqa: E402
from ...core.security.memory import SecretBytes  # noqa: E402
from ...core.vault.kdbx import VaultHandle, VaultOpenError, open_vault  # noqa: E402
from ...core.vaults.layout import VaultLayout  # noqa: E402
from ...core.vaults.registry import VaultRecord, touch_last_seen  # noqa: E402
from ..widgets import build_brand_header, build_local_key_offer_content  # noqa: E402

APP_ID = "dev.ash.PasswordManager.Login"
_log = get_logger(__name__)

_FAILURE_MESSAGES = {
    LoginFailureReason.NO_MATCHING_USB: "This USB doesn't match a registered ASH Password Manager vault.",
    LoginFailureReason.MOUNT_FAILED: "The vault's USB could not be mounted.",
    LoginFailureReason.INCORRECT_PASSWORD: "Incorrect password.",
    LoginFailureReason.VAULT_OPEN_FAILED: "The vault could not be opened -- it may be corrupted.",
}


def _make_flow(record: VaultRecord, mountpoint: str) -> LoginFlow:
    """The caller (``run_login_window``'s orchestrator) has already
    identified and mounted the USB before ever constructing a
    ``LoginWindow`` -- ``identify()``/``mount()`` here are trivial
    pass-throughs of that already-known result, so ``LoginFlow``'s
    shape (identify -> mount -> check Local Key) stays the single
    source of truth for the decision logic without this window
    re-doing USB enumeration itself."""

    def identify() -> VaultRecord | None:
        return record

    def mount(_record: VaultRecord) -> str | None:
        return mountpoint

    def unlock_local(rec: VaultRecord, mountpoint: str) -> SecretBytes:
        layout = VaultLayout.at(mountpoint, rec.container_rel_path)
        return device_registry.unlock_with_local_key(layout, rec.vault_id)

    def unlock_password(rec: VaultRecord, mountpoint: str, password: SecretBytes) -> SecretBytes:
        layout = VaultLayout.at(mountpoint, rec.container_rel_path)
        return device_registry.unlock_with_password(layout, password)

    return LoginFlow(identify_usb=identify, mount=mount, unlock_with_local_key=unlock_local, unlock_with_password=unlock_password)


class LoginWindow(Adw.ApplicationWindow):
    """One login attempt for one already-mounted, already-identified
    vault. The caller (``run_login_window``) is responsible for USB
    identification/mounting -- this window only drives
    authentication."""

    def __init__(self, app: "LoginApp", record: VaultRecord, mountpoint: str) -> None:
        super().__init__(application=app, default_width=420, default_height=460, title="ASH Password Manager")
        self._record = record
        self._mountpoint = mountpoint
        self._layout = VaultLayout.at(mountpoint, record.container_rel_path)
        self._flow = _make_flow(record, mountpoint)
        self.result_handle: VaultHandle | None = None

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar(show_title=False))
        self.set_content(toolbar_view)

        self._stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.NONE)
        toolbar_view.set_content(self._stack)

        self._stack.add_named(self._build_checking_page(), "checking")
        self._stack.add_named(self._build_password_page(), "password")
        self._stack.add_named(self._build_register_offer_page(), "register_offer")
        self._stack.add_named(self._build_error_page(), "error")
        self._stack.set_visible_child_name("checking")

        GLib.timeout_add(150, self._start_auto_login)

    # -- page builders -----------------------------------------------------

    def _build_checking_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
        box.append(build_brand_header("Login"))
        self._checking_detail = Gtk.Label(label="USB detected", xalign=0.5)
        self._checking_detail.add_css_class("ash-subtitle")
        box.append(self._checking_detail)
        self._spinner = Gtk.Spinner(width_request=32, height_request=32, spinning=True)
        box.append(self._spinner)
        self._checking_status = Gtk.Label(label="Checking for a Local Key…")
        box.append(self._checking_status)
        return box

    def _build_password_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=24, margin_bottom=24, margin_start=32, margin_end=32)
        box.append(build_brand_header("Login"))
        self._password_note = Gtk.Label(label="USB detected", xalign=0.5)
        self._password_note.add_css_class("ash-subtitle")
        box.append(self._password_note)

        group = Adw.PreferencesGroup()
        self._password_row = Adw.PasswordEntryRow(title="Password")
        self._password_row.connect("entry-activated", lambda _r: self._on_submit_password(None))
        group.add(self._password_row)
        box.append(group)

        self._password_error = Gtk.Label(xalign=0)
        self._password_error.add_css_class("pm-error-label")
        self._password_error.set_visible(False)
        box.append(self._password_error)

        login_btn = Gtk.Button(label="Login", hexpand=True)
        login_btn.add_css_class("suggested-action")
        login_btn.connect("clicked", self._on_submit_password)
        box.append(login_btn)

        hint = Gtk.Label(
            label="First time on this device? Signing in will offer to register it.",
            xalign=0.5,
            wrap=True,
        )
        hint.add_css_class("dim-label")
        box.append(hint)
        return box

    def _build_register_offer_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, valign=Gtk.Align.CENTER, margin_start=32, margin_end=32)
        box.append(build_brand_header("Create Local Key"))
        desc = Gtk.Label(
            label="Create a device key for passwordless login on this device?",
            wrap=True,
            xalign=0.5,
        )
        box.append(desc)
        box.append(build_local_key_offer_content(self._on_skip_register, self._on_generate_key))
        return box

    def _build_error_page(self) -> Gtk.Widget:
        self._error_status = Adw.StatusPage(title="Can't sign in", icon_name="dialog-error-symbolic")
        return self._error_status

    # -- flow driving --------------------------------------------------------

    def _start_auto_login(self) -> bool:
        run_blocking_async(lambda: attempt_automatic_login(self._flow), self._on_auto_login_result)
        return False

    def _on_auto_login_result(self, outcome: LoginOutcome) -> None:
        if outcome.state == LoginState.MANAGER:
            self._checking_detail.set_label("USB detected")
            self._checking_status.set_label("Local Key available -- authenticating…")
            GLib.timeout_add(300, lambda: (self._finish_unlock(outcome), False)[1])
            return
        if outcome.state == LoginState.ASK_PASSWORD:
            if outcome.fallback_used:
                self._password_note.set_label("USB detected -- enter your master password")
            self._stack.set_visible_child_name("password")
            self._password_row.grab_focus()
            return
        self._show_failure(outcome.failure)

    def _on_submit_password(self, _btn) -> None:
        password_text = self._password_row.get_text()
        if not password_text:
            return
        self._password_error.set_visible(False)
        self._password_row.set_sensitive(False)
        password = SecretBytes(password_text)
        run_blocking_async(
            lambda: self._flow.submit_password(self._record, self._mountpoint, password),
            self._on_password_result,
        )

    def _on_password_result(self, outcome: LoginOutcome) -> None:
        self._password_row.set_sensitive(True)
        if outcome.state == LoginState.MANAGER:
            self._finish_unlock(outcome)
            return
        self._password_error.set_text(_FAILURE_MESSAGES.get(outcome.failure, "Incorrect password."))
        self._password_error.set_visible(True)
        self._password_row.set_text("")
        self._password_row.grab_focus()

    def _finish_unlock(self, outcome: LoginOutcome) -> None:
        vms = outcome.vms
        try:
            password_str = vms_to_kdbx_password(vms)
            handle = open_vault(self._layout.kdbx_path, self._layout.keyfile_path, SecretBytes(password_str))
        except VaultOpenError:
            _log.warning("vault open failed after key-slot unlock", extra=safe_extra(event="vault_open_failed"))
            vms.wipe()
            self._show_failure(LoginFailureReason.VAULT_OPEN_FAILED)
            return

        touch_last_seen(self._record.vault_id)

        if not outcome.used_local_key and not local_key_store.has_local_key(self._record.vault_id):
            # Offer to register this device (spec section 5). VMS must
            # stay alive until the user decides -- there is no way to
            # re-derive it without re-prompting for the password, which
            # this flow deliberately never does. Skip wipes it
            # immediately below; Generate Key consumes and wipes it in
            # _on_generate_key.
            self._pending_handle = handle
            self._pending_vms = vms
            self._stack.set_visible_child_name("register_offer")
            return

        vms.wipe()
        self.result_handle = handle
        self.close()

    def _on_skip_register(self, _btn) -> None:
        pending_vms = getattr(self, "_pending_vms", None)
        if pending_vms is not None:
            pending_vms.wipe()
            self._pending_vms = None
        self.result_handle = self._pending_handle
        self.close()

    def _on_generate_key(self, _btn) -> None:
        vms = self._pending_vms
        self._pending_vms = None

        def work() -> bool:
            try:
                device_registry.register_device(self._layout, self._record.vault_id, vms, default_device_label())
                return True
            except Exception:  # noqa: BLE001 - best-effort; user can retry from Settings -> Devices later
                return False
            finally:
                vms.wipe()

        run_blocking_async(work, self._on_register_done)

    def _on_register_done(self, ok: bool) -> None:
        if ok:
            notify.notify_device_registered(default_device_label())
        self.result_handle = self._pending_handle
        self.close()

    def _show_failure(self, reason: LoginFailureReason | None) -> None:
        self._error_status.set_description(_FAILURE_MESSAGES.get(reason, "Something went wrong."))
        self._stack.set_visible_child_name("error")


class LoginApp(Adw.Application):
    def __init__(self, record: VaultRecord, mountpoint: str) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self._record = record
        self._mountpoint = mountpoint
        self.result_handle: VaultHandle | None = None
        self._window: LoginWindow | None = None

    def do_activate(self) -> None:
        # Same re-entrancy guard as SetupApp/PasswordManagerApp -- a
        # second "activate" (e.g. relayed over D-Bus from another CLI
        # invocation while this one is already running) must focus the
        # existing window, never silently create a duplicate.
        if self._window is None:
            self._window = LoginWindow(self, self._record, self._mountpoint)
            self._window.connect("close-request", self._on_window_closed)
        self._window.present()

    def _on_window_closed(self, window: LoginWindow) -> bool:
        self.result_handle = window.result_handle
        GLib.idle_add(self.quit)
        return False


def run_login_window(record: VaultRecord, mountpoint: str) -> VaultHandle | None:
    app = LoginApp(record, mountpoint)
    app.run(None)
    return app.result_handle
