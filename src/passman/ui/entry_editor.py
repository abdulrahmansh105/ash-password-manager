"""Create/edit an account entry (spec section 18).

Account Name, Website/Service, Username/Email, and Password are always
distinct fields -- "Account Name" is written straight to the KDBX Title
field (see ``core.vault.kdbx`` for the exact field mapping) and is never
labeled "Display Name" in the UI, matching spec section 8/18.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..core.auth.async_login import run_blocking_async
from ..core.generator import RandomPasswordPolicy, generate_random_password
from ..core.recovery.codes import RecoveryCode
from ..core.totp.totp import (
    InvalidTotpSecretError,
    TotpConfig,
    generate_totp,
    normalize_base32_secret,
)
from ..core.vault.models import CATEGORY_CHOICES, CATEGORY_LABELS, DEFAULT_CATEGORY


def _scan_qr_secret(path: str) -> str:
    """Runs on a background thread (see ``_on_import_qr``). Never
    raises -- any failure just means no secret was found."""
    try:
        result = subprocess.run(["zbarimg", "--raw", "-q", path], capture_output=True, timeout=10, check=False)
    except (subprocess.SubprocessError, OSError):
        return ""
    uri = result.stdout.decode("utf-8", errors="replace").strip()
    if not uri.startswith("otpauth://"):
        return ""
    from urllib.parse import parse_qs, urlparse

    qs = parse_qs(urlparse(uri).query)
    return qs.get("secret", [""])[0]


class TotpSetupDialog(Adw.Dialog):
    def __init__(self, on_configured) -> None:
        super().__init__(title="Add Authenticator (TOTP)", content_width=380, content_height=260)
        self._on_configured = on_configured
        self._config: TotpConfig | None = None

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        self.set_child(toolbar_view)

        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(title="Manual secret entry")

        self._secret_row = Adw.PasswordEntryRow(title="Secret (base32)")
        group.add(self._secret_row)

        error_label = Gtk.Label(xalign=0)
        error_label.add_css_class("pm-error-label")
        error_label.set_visible(False)

        test_result = Gtk.Label(xalign=0)

        def on_test(_b):
            try:
                normalized = normalize_base32_secret(self._secret_row.get_text())
                config = TotpConfig(secret_base32=normalized)
                code = generate_totp(config)
                test_result.set_text(f"Current code: {code} (changes every 30s)")
                error_label.set_visible(False)
                self._config = config
            except InvalidTotpSecretError as exc:
                error_label.set_text(str(exc))
                error_label.set_visible(True)
                test_result.set_text("")
                self._config = None

        test_btn = Gtk.Button(label="Test", hexpand=True)
        test_btn.connect("clicked", on_test)
        group.add(test_btn)
        group.add(test_result)
        group.add(error_label)

        if shutil.which("zbarimg"):
            qr_btn = Gtk.Button(label="Import from QR code image...", hexpand=True)
            qr_btn.connect("clicked", self._on_import_qr)
            group.add(qr_btn)

        save_btn = Gtk.Button(label="Enable TOTP", hexpand=True)
        save_btn.add_css_class("suggested-action")

        def on_save(_b):
            on_test(None)
            if self._config is not None:
                self._on_configured(self._config)
                self.close()

        save_btn.connect("clicked", on_save)
        group.add(save_btn)

        page.add(group)
        toolbar_view.set_content(page)

    def _on_import_qr(self, _btn) -> None:
        chooser = Gtk.FileChooserNative(title="Select QR code image", action=Gtk.FileChooserAction.OPEN)

        def on_response(dialog, response):
            if response == Gtk.ResponseType.ACCEPT:
                path = dialog.get_file().get_path()
                # `zbarimg` runs on a background thread -- it's a plain
                # subprocess.run() with a real timeout, and must not run
                # on the GTK main thread (same rule as every other
                # subprocess call in this app; see core.auth.async_login).
                run_blocking_async(lambda: _scan_qr_secret(path), self._secret_row.set_text)
            dialog.destroy()

        chooser.connect("response", on_response)
        chooser.show()


class RecoveryCodesDialog(Adw.Dialog):
    def __init__(self, on_saved) -> None:
        super().__init__(title="Add Recovery Codes", content_width=380, content_height=320)
        self._on_saved = on_saved

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        self.set_child(toolbar_view)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        hint = Gtk.Label(label="Paste one recovery code per line.", xalign=0)
        hint.add_css_class("pm-hint-label")
        box.append(hint)

        text_view = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD, top_margin=8, bottom_margin=8, left_margin=8, right_margin=8)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.add_css_class("card")
        scroller.set_child(text_view)
        box.append(scroller)

        save_btn = Gtk.Button(label="Save Recovery Codes", hexpand=True)
        save_btn.add_css_class("suggested-action")

        def on_save(_b):
            buf = text_view.get_buffer()
            text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
            codes = [RecoveryCode(code=line.strip()) for line in text.splitlines() if line.strip()]
            if codes:
                self._on_saved(codes)
            self.close()

        save_btn.connect("clicked", on_save)
        box.append(save_btn)
        toolbar_view.set_content(box)


class EntryEditorDialog(Adw.Dialog):
    def __init__(self, app, on_saved, entry_uuid: str | None = None) -> None:
        is_edit = entry_uuid is not None
        super().__init__(title="Edit Entry" if is_edit else "Create Entry", content_width=460, content_height=560)
        self._app = app
        self._on_saved = on_saved
        self._entry_uuid = entry_uuid
        self._totp_config: TotpConfig | None = None
        self._recovery_codes: list[RecoveryCode] = []

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        self.set_child(toolbar_view)

        page = Adw.PreferencesPage()

        identity_group = Adw.PreferencesGroup(title="Account")
        self._name_row = Adw.EntryRow(title="Account Name")
        self._service_row = Adw.EntryRow(title="Website / Service")
        self._username_row = Adw.EntryRow(title="Username / Email")
        self._category_row = Adw.ComboRow(
            title="Category",
            model=Gtk.StringList.new([CATEGORY_LABELS[c] for c in CATEGORY_CHOICES]),
        )
        identity_group.add(self._name_row)
        identity_group.add(self._service_row)
        identity_group.add(self._username_row)
        identity_group.add(self._category_row)
        page.add(identity_group)

        password_group = Adw.PreferencesGroup(title="Password")
        self._password_row = Adw.PasswordEntryRow(title="Password")
        password_group.add(self._password_row)
        gen_btn = Gtk.Button(label="Generate Password", hexpand=True)
        gen_btn.set_margin_top(8)
        gen_btn.connect("clicked", self._on_generate_password)
        password_group.add(gen_btn)
        page.add(password_group)

        auth_group = Adw.PreferencesGroup(title="Authentication")
        self._totp_status = Gtk.Label(label="Not configured", xalign=0)
        auth_group.add(self._totp_status)
        totp_btn = Gtk.Button(label="Add TOTP")
        totp_btn.connect("clicked", self._on_add_totp)
        auth_group.add(totp_btn)
        page.add(auth_group)

        recovery_group = Adw.PreferencesGroup(title="Recovery Codes")
        self._recovery_status = Gtk.Label(label="None saved", xalign=0)
        recovery_group.add(self._recovery_status)
        recovery_btn = Gtk.Button(label="Add Recovery Codes")
        recovery_btn.connect("clicked", self._on_add_recovery_codes)
        recovery_group.add(recovery_btn)
        page.add(recovery_group)

        notes_group = Adw.PreferencesGroup(title="Notes")
        self._notes_view = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD)
        notes_scroller = Gtk.ScrolledWindow(min_content_height=80)
        notes_scroller.set_child(self._notes_view)
        notes_group.add(notes_scroller)
        page.add(notes_group)

        toolbar_view.set_content(page)

        if is_edit:
            self._load_existing(entry_uuid, totp_btn)

        save_btn = Gtk.Button(label="Save Changes" if is_edit else "Save Entry", hexpand=True)
        save_btn.add_css_class("suggested-action")
        save_btn.add_css_class("pm-generate-button")
        save_btn.connect("clicked", self._on_save)
        bottom_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        bottom_bar.set_margin_start(16)
        bottom_bar.set_margin_end(16)
        bottom_bar.set_margin_top(8)
        bottom_bar.set_margin_bottom(16)
        bottom_bar.append(save_btn)
        toolbar_view.add_bottom_bar(bottom_bar)

    def _load_existing(self, entry_uuid: str, totp_btn: Gtk.Button) -> None:
        secrets = self._app.session.vault().get_account_secrets(entry_uuid)
        try:
            self._name_row.set_text(secrets.display_name)
            self._service_row.set_text(secrets.service_name)
            self._username_row.set_text(secrets.username)
            self._password_row.set_text(secrets.password.to_str())
            buf = self._notes_view.get_buffer()
            buf.set_text(secrets.notes or "")
            if secrets.totp is not None:
                self._totp_config = secrets.totp
                self._totp_status.set_label("Configured")
                totp_btn.set_label("Replace TOTP")
            if secrets.recovery_codes:
                self._recovery_codes = list(secrets.recovery_codes)
                self._recovery_status.set_label(f"{len(self._recovery_codes)} codes saved")
            self._category_row.set_selected(CATEGORY_CHOICES.index(secrets.category))
        finally:
            secrets.wipe()

    def _on_generate_password(self, _btn) -> None:
        policy = RandomPasswordPolicy(length=24)
        self._password_row.set_text(generate_random_password(policy))

    def _on_add_totp(self, _btn) -> None:
        def on_configured(config: TotpConfig) -> None:
            self._totp_config = config
            self._totp_status.set_label("Configured")

        TotpSetupDialog(on_configured).present(self)

    def _on_add_recovery_codes(self, _btn) -> None:
        def on_saved(codes: list[RecoveryCode]) -> None:
            self._recovery_codes = codes
            self._recovery_status.set_label(f"{len(codes)} codes saved")

        RecoveryCodesDialog(on_saved).present(self)

    def _on_save(self, _btn) -> None:
        vault = self._app.session.vault()
        buf = self._notes_view.get_buffer()
        notes = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        app_identifiers = [self._service_row.get_text().lower()] if self._service_row.get_text() else []
        selected_index = self._category_row.get_selected()
        category = CATEGORY_CHOICES[selected_index] if 0 <= selected_index < len(CATEGORY_CHOICES) else DEFAULT_CATEGORY

        if self._entry_uuid is not None:
            entry_uuid = self._entry_uuid
            vault.update_account_fields(
                entry_uuid,
                display_name=self._name_row.get_text(),
                service_name=self._service_row.get_text(),
                username=self._username_row.get_text(),
                password=self._password_row.get_text(),
                notes=notes,
                app_identifiers=json.dumps(app_identifiers),
                category=category,
            )
        else:
            entry_uuid = vault.create_account(
                display_name=self._name_row.get_text(),
                service_name=self._service_row.get_text(),
                username=self._username_row.get_text(),
                password=self._password_row.get_text(),
                url="",
                notes=notes,
                app_identifiers=app_identifiers,
                category=category,
            )
        if self._totp_config is not None:
            vault.set_totp(entry_uuid, self._totp_config, issuer=self._service_row.get_text())
        if self._recovery_codes:
            vault.set_recovery_codes(entry_uuid, self._recovery_codes)
        vault.save()

        self._totp_config = None
        self._recovery_codes = []
        self._on_saved()
        self.close()
