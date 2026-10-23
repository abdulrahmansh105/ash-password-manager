"""Account detail / reveal dialog (spec section 15: recovery codes must
require an explicit "Reveal" action, preferably with a second
confirmation, and never appear automatically).

Opened from a manager entry or secondary-click on the legacy account
picker. Real Auto-Type requires a separate confirmation and target handoff.
"""

from __future__ import annotations

import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from ..core.auth.async_login import run_blocking_async
from ..core.auth.detection import get_active_window_context
from ..core.auth.engine import LoginEngine, LoginOutcome, SafetyGuardMode
from ..core.auth.strategy import AuthStrategy
from ..core.recovery.codes import RevealGate
from ..input import select_backend
from .entry_editor import EntryEditorDialog
from .strategy_editor import StrategyEditorDialog
from .widgets import icon_button, page_intro, style_window


class AccountDetailDialog(Adw.Dialog):
    def __init__(self, app, entry_uuid: str, on_changed) -> None:
        super().__init__(title="Account Details", content_width=560, content_height=680)
        style_window(self, app.settings)
        self._reveal_timer = None
        self._autotype_running = False
        self.connect("closed", self._on_closed)
        self._app = app
        self._entry_uuid = entry_uuid
        self._on_changed = on_changed
        self._reveal_gate = RevealGate(ttl_seconds=10.0)

        toolbar_view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        edit_btn = Gtk.Button(label="Edit")
        edit_btn.connect("clicked", self._on_edit)
        header.pack_start(edit_btn)
        toolbar_view.add_top_bar(header)
        self._toast = Adw.ToastOverlay()
        self._toast.set_child(toolbar_view)
        self.set_child(self._toast)

        page = Adw.PreferencesPage()

        info_group = Adw.PreferencesGroup(title="Account")
        secrets = self._app.session.vault().get_account_secrets(entry_uuid)
        try:
            page.add(page_intro(secrets.display_name, secrets.service_name or "Account details"))
            for title, value, field in (("Username / email", secrets.username, "username"), ("Website", secrets.url, "url")):
                if value:
                    row = Adw.ActionRow(title=title, subtitle=GLib.markup_escape_text(value))
                    row.set_subtitle_lines(2)
                    copy = icon_button("edit-copy-symbolic", f"Copy {title.lower()}", lambda _b, key=field: self._copy_field(key))
                    copy.set_valign(Gtk.Align.CENTER)
                    row.add_suffix(copy)
                    info_group.add(row)
            notes = secrets.notes
            has_totp = secrets.totp is not None
            has_recovery = bool(secrets.recovery_codes)
            has_username = bool(secrets.username)
            has_password = bool(secrets.password)
            display_name = secrets.display_name
            service_name = secrets.service_name
            app_identifiers = secrets.app_identifiers
        finally:
            secrets.wipe()
        page.add(info_group)

        auth_flow_group = Adw.PreferencesGroup(
            title="Authentication Flow",
            description="How full sign-in fills this account's fields, in order.",
        )
        self._autotype_btn = Gtk.Button(label="Auto-Type", hexpand=True)
        self._autotype_btn.connect("clicked", self._on_autotype)
        auth_flow_group.add(self._autotype_btn)
        edit_strategy_btn = Gtk.Button(label="Edit Auto-Type Strategy", hexpand=True)
        edit_strategy_btn.connect(
            "clicked",
            lambda _b: StrategyEditorDialog(
                self._app,
                entry_uuid,
                display_name,
                service_name,
                has_totp,
                has_username,
                has_password,
                app_identifiers,
                on_saved=lambda: None,
            ).present(self),
        )
        auth_flow_group.add(edit_strategy_btn)

        password_group = Adw.PreferencesGroup(title="Password")
        self._password_label = Gtk.Label(label="••••••••", xalign=0)
        self._password_label.add_css_class("pm-password-row")
        self._password_label.add_css_class("pm-secret-surface")
        self._password_label.set_wrap(True)
        password_group.add(self._password_label)
        reveal_pw_btn = Gtk.Button(label="Reveal password (10s)", hexpand=True)
        reveal_pw_btn.connect("clicked", self._on_reveal_password)
        self._reveal_pw_btn = reveal_pw_btn
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_top=8)
        actions.append(reveal_pw_btn)
        copy_pw = icon_button("edit-copy-symbolic", "Copy password", lambda _b: self._copy_field("password"))
        actions.append(copy_pw)
        password_group.add(actions)
        page.add(password_group)

        if has_totp:
            totp_group = Adw.PreferencesGroup(title="Authenticator", description="Generate a current one-time sign-in code when you need it.")
            copy_totp = Gtk.Button(label="Copy current code")
            copy_totp.connect("clicked", lambda _b: self._copy_field("totp"))
            totp_group.add(copy_totp)
            page.add(totp_group)
        if notes:
            notes_group = Adw.PreferencesGroup(title="Notes")
            note_label = Gtk.Label(label=notes, xalign=0, wrap=True, selectable=True)
            note_label.add_css_class("pm-secret-surface")
            notes_group.add(note_label)
            page.add(notes_group)
        page.add(auth_flow_group)

        if has_recovery:
            recovery_group = Adw.PreferencesGroup(title="Recovery Codes")
            self._recovery_status = Gtk.Label(label="Hidden", xalign=0)
            recovery_group.add(self._recovery_status)
            self._recovery_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, visible=False)
            self._recovery_list.add_css_class("boxed-list")
            recovery_group.add(self._recovery_list)
            self._reveal_step1_btn = Gtk.Button(label="Reveal Recovery Codes", hexpand=True)
            self._reveal_step1_btn.connect("clicked", self._on_reveal_recovery_step1)
            recovery_group.add(self._reveal_step1_btn)
            page.add(recovery_group)

        danger_group = Adw.PreferencesGroup(title="Danger zone")
        if has_totp:
            remove_totp_btn = Gtk.Button(label="Remove TOTP", hexpand=True)
            remove_totp_btn.connect("clicked", self._on_remove_totp)
            danger_group.add(remove_totp_btn)
        delete_btn = Gtk.Button(label="Delete Account", hexpand=True)
        if has_totp:
            delete_btn.set_margin_top(8)
        delete_btn.add_css_class("destructive-action")
        delete_btn.connect("clicked", self._on_delete)
        danger_group.add(delete_btn)
        page.add(danger_group)

        toolbar_view.set_content(page)

    def _on_edit(self, _btn: Gtk.Button) -> None:
        def on_saved() -> None:
            self._on_changed()
            self.close()

        EntryEditorDialog(self._app, on_saved=on_saved, entry_uuid=self._entry_uuid).present(self)

    def _on_autotype(self, _btn) -> None:
        if self._autotype_running or not self._app.session.is_unlocked():
            return
        confirm = Adw.AlertDialog(
            heading="Auto-Type this account?",
            body=(
                "ASH will hide for 5 seconds. Switch to the target app and click its "
                "first login field. This account's strategy will type your real "
                "credentials into that window and may submit the form. Check the "
                "website and selected field before the delay ends."
            ),
        )
        confirm.add_response("cancel", "Cancel")
        confirm.add_response("type", "Start Auto-Type in 5 seconds")
        confirm.set_default_response("cancel")
        confirm.set_close_response("cancel")
        confirm.set_response_appearance("type", Adw.ResponseAppearance.SUGGESTED)
        self._autotype_running = True

        def on_response(_dialog, response):
            if response != "type" or not self._app.session.is_unlocked():
                self._autotype_running = False
                return
            parent = self.get_root()
            if not isinstance(parent, Gtk.Window):
                self._autotype_running = False
                return
            settings = self._app.settings
            parent.set_visible(False)

            def finish(result=None):
                self._autotype_running = False
                if not self._app.session.is_unlocked():
                    return
                if result is not None and result.outcome is LoginOutcome.SUCCESS:
                    message = "Auto-Type sequence completed"
                elif result is not None and result.outcome is LoginOutcome.NO_BACKEND:
                    message = "No input method available. Enable ydotoold or AT-SPI."
                else:
                    message = "Unable to complete Auto-Type. No further input was sent."
                self._toast.add_toast(Adw.Toast(title=message))
                parent.present()

            def work():
                if not self._app.session.is_unlocked():
                    return None
                context = get_active_window_context()
                if not context.app_id and not context.window_id:
                    raise RuntimeError("target window unavailable")
                backend = select_backend(
                    allow_clipboard_fallback=settings.clipboard_fallback_enabled,
                    clipboard=self._app.session.clipboard,
                    clear_after_seconds=settings.clipboard_timeout_seconds(),
                )
                if not self._app.session.is_unlocked():
                    return None
                with self._app.session.vault().get_account_secrets(self._entry_uuid) as secrets:
                    return LoginEngine(backend).run(
                        secrets, AuthStrategy.from_json(secrets.auth_strategy_json), context,
                        SafetyGuardMode(settings.safety_guard_mode), confirmed=True,
                        is_cancelled=lambda: not self._app.session.is_unlocked(),
                        context_provider=get_active_window_context,
                    )

            def start_worker():
                if not self._app.session.is_unlocked():
                    self._autotype_running = False
                    return False
                run_blocking_async(work, finish, on_error=lambda _: finish())
                return False

            GLib.timeout_add(5000, start_worker)

        confirm.connect("response", on_response)
        confirm.present(self)

    def _copy_field(self, field: str) -> None:
        from ..core.totp.totp import InvalidTotpSecretError, generate_totp
        secrets = self._app.session.vault().get_account_secrets(self._entry_uuid)
        try:
            if field == "password":
                value = secrets.password.to_str()
            elif field == "totp":
                try:
                    value = generate_totp(secrets.totp)
                except (InvalidTotpSecretError, ValueError, TypeError, AttributeError):
                    self._toast.add_toast(Adw.Toast(title="Unable to generate a code. Check the authenticator settings."))
                    return
            else:
                value = getattr(secrets, field)
            result = self._app.session.clipboard.copy(value, self._app.settings.clipboard_timeout_seconds())
            self._toast.add_toast(Adw.Toast(title="Copied to clipboard" if result.copied else "Could not copy to clipboard"))
        finally:
            secrets.wipe()

    def _hide_password(self) -> bool:
        self._password_label.set_text("••••••••")
        self._reveal_pw_btn.set_label("Reveal password (10s)")
        self._reveal_timer = None
        return False

    def _on_reveal_password(self, btn: Gtk.Button) -> None:
        if self._reveal_timer is not None:
            GLib.source_remove(self._reveal_timer)
            self._hide_password()
            return
        secrets = self._app.session.vault().get_account_secrets(self._entry_uuid)
        try:
            self._password_label.set_text(secrets.password.to_str())
        finally:
            secrets.wipe()
        btn.set_label("Hide password")
        self._reveal_timer = GLib.timeout_add_seconds(10, self._hide_password)

    def _on_closed(self, _dialog) -> None:
        if self._reveal_timer is not None:
            GLib.source_remove(self._reveal_timer)
        self._hide_password()
        recovery = getattr(self, "_recovery_list", None)
        if recovery is not None:
            while (child := recovery.get_row_at_index(0)) is not None:
                recovery.remove(child)

    def _on_reveal_recovery_step1(self, btn: Gtk.Button) -> None:
        self._reveal_gate.request(time.time())
        btn.set_label("Confirm reveal")
        btn.disconnect_by_func(self._on_reveal_recovery_step1)
        btn.connect("clicked", self._on_reveal_recovery_step2)

    def _on_reveal_recovery_step2(self, btn: Gtk.Button) -> None:
        if not self._reveal_gate.confirm(time.time()):
            self._recovery_status.set_text("Confirmation expired. Click Reveal to try again.")
            btn.set_label("Reveal Recovery Codes")
            btn.disconnect_by_func(self._on_reveal_recovery_step2)
            btn.connect("clicked", self._on_reveal_recovery_step1)
            return
        secrets = self._app.session.vault().get_account_secrets(self._entry_uuid)
        try:
            codes = list(secrets.recovery_codes)
        finally:
            secrets.wipe()
        self._recovery_status.set_text(f"{len(codes)} codes" if codes else "No codes")
        self._render_recovery_codes(codes)
        btn.set_sensitive(False)

    def _render_recovery_codes(self, codes) -> None:
        child = self._recovery_list.get_row_at_index(0)
        while child is not None:
            self._recovery_list.remove(child)
            child = self._recovery_list.get_row_at_index(0)

        for index, code in enumerate(codes):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            row.set_margin_top(4)
            row.set_margin_bottom(4)
            row.set_margin_start(8)
            row.set_margin_end(8)

            # Selectable so an intentional select+copy works (you need to
            # actually use these to recover an account) -- nothing here
            # ever copies automatically, satisfying "no accidental copy"
            # without also making the codes impossible to use.
            label = Gtk.Label(label=code.code, xalign=0, hexpand=True, selectable=True)
            label.add_css_class("pm-password-row")
            if code.used:
                label.add_css_class("dim-label")
            row.append(label)

            toggle = Gtk.Button(label="Mark unused" if code.used else "Mark used")
            toggle.connect("clicked", self._make_toggle_handler(index))
            row.append(toggle)

            self._recovery_list.append(row)
        self._recovery_list.set_visible(bool(codes))

    def _make_toggle_handler(self, index: int):
        def handler(_btn) -> None:
            secrets = self._app.session.vault().get_account_secrets(self._entry_uuid)
            try:
                codes = list(secrets.recovery_codes)
            finally:
                secrets.wipe()
            if 0 <= index < len(codes):
                codes[index].used = not codes[index].used
            vault = self._app.session.vault()
            vault.set_recovery_codes(self._entry_uuid, codes)
            vault.save()
            self._render_recovery_codes(codes)

        return handler

    def _on_remove_totp(self, _btn) -> None:
        self._app.session.vault().remove_totp(self._entry_uuid)
        self._app.session.vault().save()
        self._on_changed()
        self.close()

    def _on_delete(self, _btn) -> None:
        confirm = Adw.AlertDialog(
            heading="Delete this account?",
            body="This removes the entry from the vault. This cannot be undone.",
        )
        confirm.add_response("cancel", "Cancel")
        confirm.add_response("delete", "Delete")
        confirm.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_d, response):
            if response == "delete":
                self._app.session.vault().delete_account(self._entry_uuid)
                self._app.session.vault().save()
                self._on_changed()
                self.close()

        confirm.connect("response", on_response)
        confirm.present(self)
