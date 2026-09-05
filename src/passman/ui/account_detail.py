"""Account detail / reveal dialog (spec section 15: recovery codes must
require an explicit "Reveal" action, preferably with a second
confirmation, and never appear automatically).

Opened via secondary-click (right-click) on an account tile -- kept out
of the primary single-click path (which is full sign-in) so a stray
click never exposes anything.
"""

from __future__ import annotations

import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from ..core.recovery.codes import RevealGate
from .entry_editor import EntryEditorDialog
from .strategy_editor import StrategyEditorDialog


class AccountDetailDialog(Adw.Dialog):
    def __init__(self, app, entry_uuid: str, on_changed) -> None:
        super().__init__(title="Account Details", content_width=420, content_height=420)
        self._app = app
        self._entry_uuid = entry_uuid
        self._on_changed = on_changed
        self._reveal_gate = RevealGate(ttl_seconds=10.0)

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        self.set_child(toolbar_view)

        page = Adw.PreferencesPage()

        info_group = Adw.PreferencesGroup(title="Account")
        secrets = self._app.session.vault().get_account_secrets(entry_uuid)
        try:
            info_group.add(Gtk.Label(label=secrets.display_name, xalign=0))
            info_group.add(Gtk.Label(label=f"Username: {secrets.username}", xalign=0))
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

        edit_group = Adw.PreferencesGroup(title="Edit")
        edit_btn = Gtk.Button(label="Edit Account", hexpand=True)
        edit_btn.connect("clicked", self._on_edit)
        edit_group.add(edit_btn)
        page.add(edit_group)

        auth_flow_group = Adw.PreferencesGroup(
            title="Authentication Flow",
            description="How full sign-in fills this account's fields, in order.",
        )
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
        page.add(auth_flow_group)

        password_group = Adw.PreferencesGroup(title="Password")
        self._password_label = Gtk.Label(label="••••••••", xalign=0)
        self._password_label.add_css_class("pm-password-row")
        password_group.add(self._password_label)
        reveal_pw_btn = Gtk.Button(label="Reveal password (10s)", hexpand=True)
        reveal_pw_btn.connect("clicked", self._on_reveal_password)
        password_group.add(reveal_pw_btn)
        page.add(password_group)

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

    def _on_reveal_password(self, btn: Gtk.Button) -> None:
        secrets = self._app.session.vault().get_account_secrets(self._entry_uuid)
        try:
            self._password_label.set_text(secrets.password.to_str())
        finally:
            secrets.wipe()
        btn.set_sensitive(False)

        from gi.repository import GLib

        def rehide():
            self._password_label.set_text("••••••••")
            btn.set_sensitive(True)
            return False

        GLib.timeout_add_seconds(10, rehide)

    def _on_reveal_recovery_step1(self, btn: Gtk.Button) -> None:
        self._reveal_gate.request(time.time())
        btn.set_label("Confirm reveal")
        btn.disconnect_by_func(self._on_reveal_recovery_step1)
        btn.connect("clicked", self._on_reveal_recovery_step2)

    def _on_reveal_recovery_step2(self, btn: Gtk.Button) -> None:
        if not self._reveal_gate.confirm(time.time()):
            self._recovery_status.set_text("Reveal expired -- click Reveal again.")
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
