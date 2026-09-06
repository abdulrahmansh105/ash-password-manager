"""Settings (spec section 20). Every category from the spec is
represented; nothing here ever displays a password/TOTP secret."""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
from gi.repository import Adw, Gdk, Gtk

from ..config.store import (
    CLIPBOARD_TIMEOUT_CHOICES,
    SAFETY_GUARD_CHOICES,
    THEME_CHOICES,
    USB_REMOVAL_CHOICES,
    save_settings,
)
from ..core.backup.archive import BackupError, backup_filename, create_backup
from ..core.devices import local_key as local_key_store
from ..core.devices.registry import list_devices, reset_master_password_with_local_key, revoke_device
from ..core.security.memory import SecretBytes
from ..core.vaults.health import check_vault_health
from ..core.vaults.layout import VaultLayout
from ..integration import notify
from ..integration.shortcuts import BindResult, select_and_bind
from .widgets import accelerator_display_label as _accelerator_display_label

_USB_REMOVAL_LABELS = {"lock_immediately": "Lock immediately", "keep_unlocked": "Keep unlocked"}
_HOTKEY_EXEC_CMD = "ash-password-manager sign-in"
_IGNORED_CAPTURE_KEYVALS = {
    Gdk.KEY_Control_L, Gdk.KEY_Control_R, Gdk.KEY_Alt_L, Gdk.KEY_Alt_R,
    Gdk.KEY_Shift_L, Gdk.KEY_Shift_R, Gdk.KEY_Super_L, Gdk.KEY_Super_R,
    Gdk.KEY_Meta_L, Gdk.KEY_Meta_R, Gdk.KEY_Escape,
}


class SettingsDialog(Adw.PreferencesDialog):
    def __init__(self, app) -> None:
        super().__init__(title="Settings", content_width=520, content_height=560)
        self._app = app
        s = app.settings

        general = Adw.PreferencesPage(title="General", icon_name="preferences-system-symbolic")
        general_group = Adw.PreferencesGroup(title="Appearance")
        self._theme_row = Adw.ComboRow(title="Theme", model=Gtk.StringList.new(list(THEME_CHOICES)))
        self._theme_row.set_selected(list(THEME_CHOICES).index(s.theme))
        general_group.add(self._theme_row)
        self._density_row = Adw.ComboRow(title="Density", model=Gtk.StringList.new(["comfortable", "compact"]))
        self._density_row.set_selected(0 if s.ui_density == "comfortable" else 1)
        general_group.add(self._density_row)
        general.add(general_group)
        self.add(general)

        security = Adw.PreferencesPage(title="Security", icon_name="channel-secure-symbolic")
        sec_group = Adw.PreferencesGroup(title="Auto Lock")
        self._auto_lock_enabled_row = Adw.SwitchRow(title="Enable Auto Lock", active=s.auto_lock_enabled)
        sec_group.add(self._auto_lock_enabled_row)
        self._timeout_row = Adw.SpinRow.new_with_range(30, 3600, 30)
        self._timeout_row.set_title("Lock after (seconds)")
        self._timeout_row.set_value(max(s.inactivity_timeout_seconds, 30))
        sec_group.add(self._timeout_row)
        self._lock_screen_row = Adw.SwitchRow(title="Lock on screen lock", active=s.lock_on_screen_lock)
        sec_group.add(self._lock_screen_row)
        self._lock_suspend_row = Adw.SwitchRow(title="Lock on suspend", active=s.lock_on_suspend)
        sec_group.add(self._lock_suspend_row)
        security.add(sec_group)

        usb_removal_group = Adw.PreferencesGroup(
            title="USB Removal Protection",
            description=(
                "Your password vault is stored on the USB. When the USB is removed, ASH Password "
                "Manager can automatically lock the manager to reduce the risk of leaving the vault "
                "unlocked."
            ),
        )
        self._lock_usb_row = Adw.SwitchRow(title="Lock on USB removal", active=s.lock_on_usb_removal)
        usb_removal_group.add(self._lock_usb_row)
        usb_removal_labels = [_USB_REMOVAL_LABELS[c] for c in USB_REMOVAL_CHOICES]
        self._usb_removal_row = Adw.ComboRow(title="When USB is removed", model=Gtk.StringList.new(usb_removal_labels))
        self._usb_removal_row.set_selected(
            list(USB_REMOVAL_CHOICES).index(s.usb_removal_action) if s.usb_removal_action in USB_REMOVAL_CHOICES else 0
        )
        usb_removal_group.add(self._usb_removal_row)
        security.add(usb_removal_group)

        clip_group = Adw.PreferencesGroup(title="Clipboard")
        self._clip_fallback_row = Adw.SwitchRow(
            title="Allow clipboard fallback",
            subtitle="Off by default. When on, autotype may fall back to a clipboard paste if direct typing fails. The clipboard is auto-cleared after the timeout below.",
            active=s.clipboard_fallback_enabled,
        )
        clip_group.add(self._clip_fallback_row)
        self._clip_timeout_row = Adw.ComboRow(
            title="Clipboard auto-clear", model=Gtk.StringList.new(list(CLIPBOARD_TIMEOUT_CHOICES.keys()))
        )
        self._clip_timeout_row.set_selected(list(CLIPBOARD_TIMEOUT_CHOICES.keys()).index(s.clipboard_timeout_key))
        clip_group.add(self._clip_timeout_row)
        security.add(clip_group)

        password_page = Adw.PreferencesPage(title="Password", icon_name="dialog-password-symbolic")
        password_group = Adw.PreferencesGroup(
            title="Master Password",
            description=(
                "Reset the master password using this device's Local Key. "
                "The vault's encryption key is not changed."
            ),
        )
        self._reset_password_btn = Gtk.Button(label="Reset Master Password", hexpand=True)
        self._reset_password_btn.add_css_class("suggested-action")
        self._reset_password_btn.set_sensitive(bool(app.vault_id and local_key_store.has_local_key(app.vault_id)))
        self._reset_password_btn.connect("clicked", self._on_reset_master_password)
        password_group.add(self._reset_password_btn)
        self._reset_password_status = Gtk.Label(xalign=0, wrap=True)
        self._reset_password_status.set_visible(False)
        password_group.add(self._reset_password_status)
        password_page.add(password_group)
        self.add(password_page)
        self.add(security)

        auth = Adw.PreferencesPage(title="Authentication", icon_name="input-keyboard-symbolic")
        auth_group = Adw.PreferencesGroup(title="Autotype")
        self._typing_delay_row = Adw.SpinRow.new_with_range(0, 200, 1)
        self._typing_delay_row.set_title("Typing delay (ms)")
        self._typing_delay_row.set_value(s.typing_delay_ms)
        auth_group.add(self._typing_delay_row)
        self._login_timeout_row = Adw.SpinRow.new_with_range(500, 30000, 500)
        self._login_timeout_row.set_title("Login step timeout (ms)")
        self._login_timeout_row.set_value(s.login_step_timeout_ms)
        auth_group.add(self._login_timeout_row)
        self._retry_row = Adw.SpinRow.new_with_range(0, 5, 1)
        self._retry_row.set_title("Retry count")
        self._retry_row.set_value(s.login_retry_count)
        auth_group.add(self._retry_row)
        auth.add(auth_group)

        guard_group = Adw.PreferencesGroup(
            title="Safety Guard",
            description="Ambiguous or unrecognized windows always require confirmation, regardless of this setting.",
        )
        self._guard_row = Adw.ComboRow(title="Safety Guard mode", model=Gtk.StringList.new(list(SAFETY_GUARD_CHOICES)))
        self._guard_row.set_selected(list(SAFETY_GUARD_CHOICES).index(s.safety_guard_mode))
        guard_group.add(self._guard_row)
        auth.add(guard_group)
        self.add(auth)

        reg = app.registration
        self._layout = (
            VaultLayout.at(app.mountpoint, reg.container_rel_path)
            if app.vault_id and hasattr(reg, "container_rel_path")
            else None
        )

        vault_page = Adw.PreferencesPage(title="Vault", icon_name="drive-removable-media-symbolic")
        vault_group = Adw.PreferencesGroup(title="USB Identity")
        if getattr(reg, "name", None):
            vault_group.add(Gtk.Label(label=f"Name: {reg.name}", xalign=0))
        if getattr(reg, "luks_uuid", None):
            vault_group.add(Gtk.Label(label=f"LUKS UUID: {reg.luks_uuid}", xalign=0))
        vault_group.add(Gtk.Label(label=f"Filesystem UUID: {getattr(reg, 'filesystem_uuid', '?')}", xalign=0))
        for attr, label in (("drive_vendor", "Vendor"), ("drive_model", "Model")):
            value = getattr(reg, attr, None)
            if value:
                vault_group.add(Gtk.Label(label=f"{label}: {value}", xalign=0))
        vault_group.add(Gtk.Label(label=f"Vault: {reg.vault_rel_path}", xalign=0))
        vault_group.add(Gtk.Label(label=f"Key File: {reg.keyfile_rel_path}", xalign=0))
        vault_page.add(vault_group)

        if self._layout is not None:
            health_group = Adw.PreferencesGroup(title="Vault Health")
            self._health_status_label = Gtk.Label(xalign=0)
            health_group.add(self._health_status_label)
            check_btn = Gtk.Button(label="Check Vault Health")
            check_btn.connect("clicked", self._on_check_health)
            health_group.add(check_btn)
            vault_page.add(health_group)
            self._on_check_health(None)
        else:
            hint = Gtk.Label(
                label="This vault uses the original key-file-only format. Adopt it into ASH Password "
                "Manager's format (Devices/Backup below) to unlock device management.",
                xalign=0,
                wrap=True,
            )
            hint.add_css_class("pm-hint-label")
            vault_page.add(hint)
        self.add(vault_page)

        if self._layout is not None:
            self.add(self._build_devices_page())
        self.add(self._build_shortcuts_page(s))
        if self._layout is not None:
            self.add(self._build_backup_page())

        accounts_page = Adw.PreferencesPage(title="Accounts", icon_name="avatar-default-symbolic")
        accounts_group = Adw.PreferencesGroup()
        self._suggest_row = Adw.SwitchRow(title="Suggest matching account", active=s.suggested_account_enabled)
        accounts_group.add(self._suggest_row)
        self._icon_cache_row = Adw.SwitchRow(title="Use icon cache", active=s.icon_cache_enabled)
        accounts_group.add(self._icon_cache_row)
        accounts_page.add(accounts_group)
        self.add(accounts_page)

        advanced = Adw.PreferencesPage(title="Advanced", icon_name="applications-engineering-symbolic")
        advanced_group = Adw.PreferencesGroup()
        self._diagnostic_row = Adw.SwitchRow(
            title="Diagnostic mode",
            subtitle="Extra non-secret status logging. Never logs passwords, TOTP secrets, or recovery codes.",
            active=s.diagnostic_mode,
        )
        advanced_group.add(self._diagnostic_row)
        advanced.add(advanced_group)
        self.add(advanced)

        self.connect("closed", self._on_closed)

    def _on_closed(self, _dialog) -> None:
        s = self._app.settings
        s.theme = list(THEME_CHOICES)[self._theme_row.get_selected()]
        s.ui_density = "comfortable" if self._density_row.get_selected() == 0 else "compact"
        s.auto_lock_enabled = self._auto_lock_enabled_row.get_active()
        s.inactivity_timeout_seconds = int(self._timeout_row.get_value())
        s.lock_on_screen_lock = self._lock_screen_row.get_active()
        s.lock_on_suspend = self._lock_suspend_row.get_active()
        s.lock_on_usb_removal = self._lock_usb_row.get_active()
        s.usb_removal_action = list(USB_REMOVAL_CHOICES)[self._usb_removal_row.get_selected()]
        s.clipboard_fallback_enabled = self._clip_fallback_row.get_active()
        s.clipboard_timeout_key = list(CLIPBOARD_TIMEOUT_CHOICES.keys())[self._clip_timeout_row.get_selected()]
        s.typing_delay_ms = int(self._typing_delay_row.get_value())
        s.login_step_timeout_ms = int(self._login_timeout_row.get_value())
        s.login_retry_count = int(self._retry_row.get_value())
        s.safety_guard_mode = list(SAFETY_GUARD_CHOICES)[self._guard_row.get_selected()]
        s.suggested_account_enabled = self._suggest_row.get_active()
        s.icon_cache_enabled = self._icon_cache_row.get_active()
        s.diagnostic_mode = self._diagnostic_row.get_active()
        save_settings(s)
        self._app.session.inactivity_timeout_seconds = s.effective_auto_lock_timeout_seconds()

    def _on_reset_master_password(self, _btn) -> None:
        new_pw = Adw.PasswordEntryRow(title="New master password")
        confirm_pw = Adw.PasswordEntryRow(title="Confirm new master password")
        page = Adw.PreferencesPage(title="Reset Master Password")
        group = Adw.PreferencesGroup(description="Authenticated by this device's Local Key.")
        group.add(new_pw)
        group.add(confirm_pw)
        status = Gtk.Label(xalign=0, wrap=True)
        status.set_visible(False)
        group.add(status)
        page.add(group)

        dialog = Adw.Dialog(title="Reset Master Password", content_width=420, content_height=320)
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar(show_title=True)
        toolbar.add_top_bar(header)
        toolbar.set_content(page)
        dialog.set_child(toolbar)

        save_btn = Gtk.Button(label="Set New Password")
        save_btn.add_css_class("suggested-action")
        header.pack_end(save_btn)

        def submit(_btn) -> None:
            first = new_pw.get_text()
            second = confirm_pw.get_text()
            if not first or first != second:
                status.set_text("Enter the same new password in both fields.")
                status.set_visible(True)
                return
            save_btn.set_sensitive(False)
            self._reset_password_btn.set_sensitive(False)
            secret = SecretBytes(first)

            def work() -> str | None:
                try:
                    reset_master_password_with_local_key(
                        self._layout, self._app.vault_id, secret
                    )
                    return None
                except Exception as exc:
                    return type(exc).__name__
                finally:
                    secret.wipe()

            def done(error_name: str | None) -> None:
                save_btn.set_sensitive(True)
                self._reset_password_btn.set_sensitive(error_name is None)
                if error_name is None:
                    dialog.close()
                    self._reset_password_status.set_text("Master password updated successfully using the Local Key.")
                else:
                    status.set_text("Could not reset the master password. The Local Key may be unavailable or revoked.")
                    status.set_visible(True)
                    self._reset_password_status.set_text("Reset failed. No password was changed.")
                self._reset_password_status.set_visible(True)

            from ..core.auth.async_login import run_blocking_async
            run_blocking_async(work, done)

        save_btn.connect("clicked", submit)
        dialog.present(self)

    # -- Vault health ---------------------------------------------------------

    def _on_check_health(self, _btn) -> None:
        report = check_vault_health(self._layout)
        icon = {"ok": "✓", "warning": "⚠", "error": "✗"}[report.status.value]
        lines = [f"{icon} {c.name}: {c.detail}" for c in report.checks]
        self._health_status_label.set_label("\n".join(lines))
        self._health_status_label.set_wrap(True)

    # -- Devices ---------------------------------------------------------------

    def _build_devices_page(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title="Devices", icon_name="computer-symbolic")
        this_group = Adw.PreferencesGroup(title="This Device")
        has_key = local_key_store.has_local_key(self._app.vault_id)
        identity = local_key_store.load_identity(self._app.vault_id) if has_key else None
        this_group.add(Gtk.Label(label="✓ Registered", xalign=0))
        this_group.add(
            Gtk.Label(
                label=f"Local Key: {'Enabled (' + identity.tier + ')' if identity else 'Not enabled'}", xalign=0
            )
        )
        page.add(this_group)

        other_group = Adw.PreferencesGroup(title="Other Devices")
        my_device_id = identity.device_id if identity else None
        devices = [d for d in list_devices(self._layout) if d.device_id != my_device_id]
        if not devices:
            other_group.add(Gtk.Label(label="No other devices registered", xalign=0))
        for device in devices:
            row = Adw.ActionRow(
                title=device.label,
                subtitle=("Revoked" if device.is_revoked else f"Last seen: {device.last_seen_utc or 'never'}"),
            )
            if not device.is_revoked:
                revoke_btn = Gtk.Button(label="Revoke", valign=Gtk.Align.CENTER)
                revoke_btn.add_css_class("destructive-action")
                revoke_btn.connect("clicked", self._make_revoke_handler(device.device_id, device.label, page))
                row.add_suffix(revoke_btn)
            other_group.add(row)
        page.add(other_group)
        return page

    def _make_revoke_handler(self, device_id: str, device_label: str, page: Adw.PreferencesPage):
        def handler(_btn) -> None:
            dialog = Adw.AlertDialog(
                heading="Revoke this device?",
                body="It will no longer be able to unlock this vault with its Local Key.",
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("revoke", "Revoke")
            dialog.set_response_appearance("revoke", Adw.ResponseAppearance.DESTRUCTIVE)

            def on_response(_d, response: str) -> None:
                if response == "revoke":
                    revoke_device(self._layout, device_id)
                    notify.notify_device_revoked(device_label)
                    self._refresh_devices_page(page)

            dialog.connect("response", on_response)
            dialog.present(self)

        return handler

    def _refresh_devices_page(self, page: Adw.PreferencesPage) -> None:
        # Adw.PreferencesPage has no simple "clear" API; rebuilding the
        # whole dialog content is unnecessary here -- closing and
        # reopening Settings shows the change, which is an acceptable
        # cost for a rare action (device revocation).
        toast = Adw.Toast(title="Device revoked. Reopen Settings to refresh this list.", timeout=4)
        self.add_toast(toast)

    # -- Shortcuts ---------------------------------------------------------

    def _build_shortcuts_page(self, s) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title="Shortcuts", icon_name="preferences-desktop-keyboard-symbolic")
        group = Adw.PreferencesGroup(
            title="Open Manager Hotkey", description="Click Record, then press the key combination you want."
        )
        self._pending_accelerator: str | None = s.hotkey_accelerator or None
        self._recording_hotkey = False

        current = _accelerator_display_label(s.hotkey_accelerator) if s.hotkey_accelerator else "Not configured"
        self._hotkey_current_label = Gtk.Label(label=f"Current shortcut: {current}", xalign=0)
        group.add(self._hotkey_current_label)

        self._hotkey_record_btn = Gtk.Button(label="Record New Shortcut...", hexpand=True)
        self._hotkey_record_btn.connect("clicked", self._on_start_recording_hotkey)
        group.add(self._hotkey_record_btn)

        self._hotkey_result_label = Gtk.Label(xalign=0, wrap=True)
        self._hotkey_result_label.set_visible(False)
        group.add(self._hotkey_result_label)

        apply_btn = Gtk.Button(label="Apply Shortcut", hexpand=True)
        apply_btn.add_css_class("suggested-action")
        apply_btn.connect("clicked", self._on_apply_hotkey)
        group.add(apply_btn)
        page.add(group)

        key_controller = Gtk.EventControllerKey()
        key_controller.connect("key-pressed", self._on_hotkey_key_pressed)
        self.add_controller(key_controller)
        return page

    def _on_start_recording_hotkey(self, _btn) -> None:
        self._recording_hotkey = True
        self._hotkey_record_btn.set_label("Press a key combination…")
        self._hotkey_result_label.set_visible(False)

    def _on_hotkey_key_pressed(self, _controller, keyval, _keycode, state) -> bool:
        if not self._recording_hotkey:
            return False
        if keyval in _IGNORED_CAPTURE_KEYVALS:
            return True
        mods = state & Gtk.accelerator_get_default_mod_mask()
        if not Gtk.accelerator_valid(keyval, mods):
            return True
        accelerator = Gtk.accelerator_name(keyval, mods)
        self._recording_hotkey = False
        self._pending_accelerator = accelerator
        self._hotkey_record_btn.set_label("Record New Shortcut...")
        self._hotkey_result_label.set_label(f"Captured: {_accelerator_display_label(accelerator)} -- click Apply to use it.")
        self._hotkey_result_label.set_visible(True)
        return True

    def _on_apply_hotkey(self, _btn) -> None:
        accelerator = self._pending_accelerator
        if not accelerator:
            self._hotkey_result_label.set_label("Click Record and press a key combination first.")
            self._hotkey_result_label.set_visible(True)
            return
        backend, outcome = select_and_bind(accelerator, _HOTKEY_EXEC_CMD, "Open ASH Password Manager")
        s = self._app.settings
        if outcome.result == BindResult.OK:
            s.hotkey_accelerator = accelerator
            s.hotkey_backend = backend.name
            save_settings(s)
            self._hotkey_current_label.set_label(f"Current shortcut: {_accelerator_display_label(accelerator)}")
            self._hotkey_result_label.set_label(f"Applied via {backend.name}.")
        else:
            self._hotkey_result_label.set_label(outcome.detail or f"Could not apply via {backend.name}.")
        self._hotkey_result_label.set_visible(True)

    # -- Backup ---------------------------------------------------------------

    def _build_backup_page(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title="Backup", icon_name="document-save-symbolic")
        group = Adw.PreferencesGroup(
            title="Create Encrypted Backup",
            description=(
                "Backs up the vault, key file, and device roster -- never Local Keys, and never the "
                "master secret in any recoverable form. Restoring always requires the master password "
                "and registers the restoring device as new."
            ),
        )
        self._backup_passphrase_row = Adw.PasswordEntryRow(title="Backup passphrase")
        group.add(self._backup_passphrase_row)
        self._backup_result_label = Gtk.Label(xalign=0, wrap=True)
        self._backup_result_label.set_visible(False)
        group.add(self._backup_result_label)
        create_btn = Gtk.Button(label="Create Backup...", hexpand=True)
        create_btn.add_css_class("suggested-action")
        create_btn.connect("clicked", self._on_create_backup)
        group.add(create_btn)
        page.add(group)
        return page

    def _on_create_backup(self, _btn) -> None:
        passphrase_text = self._backup_passphrase_row.get_text()
        if not passphrase_text:
            return
        chooser = Gtk.FileChooserNative(title="Save Backup", action=Gtk.FileChooserAction.SAVE)
        reg = self._app.registration
        chooser.set_current_name(backup_filename(getattr(reg, "name", "vault")))

        def on_response(dialog, response) -> None:
            if response == Gtk.ResponseType.ACCEPT:
                path = dialog.get_file().get_path()
                try:
                    create_backup(self._layout, Path(path), SecretBytes(passphrase_text))
                    notify.notify_backup_created(path)
                    self._backup_result_label.set_label(f"Backup created: {path}")
                except BackupError as exc:
                    self._backup_result_label.set_label(f"Backup failed: {exc}")
                self._backup_result_label.set_visible(True)
                self._backup_passphrase_row.set_text("")
            dialog.destroy()

        chooser.connect("response", on_response)
        chooser.show()
