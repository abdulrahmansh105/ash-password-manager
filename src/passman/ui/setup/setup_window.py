"""First-time setup wizard (spec sections 2-11, 26, 35).

::

    USB_SELECTION -> [ADOPT_OR_CREATE] -> PASSWORD_CREATION -> LOCAL_KEY_OPTIONAL
        -> VAULT_CREATION -> DEVICE_REGISTRATION -> HOTKEY_SETUP
        -> USB_REMOVAL_CONFIGURATION -> SETUP_COMPLETE

Drives ``core.flows.setup_machine.SetupFlow`` through a linear
``Adw.NavigationView``, one page per state -- the wizard's own page
order matches the state machine's transition rules exactly, in
particular committing the vault (``core.vault.provisioning``, already
transactional on its own) *right after* the Local Key choice, before
Hotkey/USB-removal configuration -- exactly the order spec section 35
draws, not "collect everything then commit at the end". Hotkey and
USB-removal are local app settings only; configuring them after the
vault already exists is safe and means closing the wizard partway
through them still leaves a fully valid, usable vault behind (spec
section 26: no partially initialized account).
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from ...config.store import load_settings, save_settings
from ...core.auth.async_login import run_blocking_async
from ...core.crypto.keyslots import vms_to_kdbx_password
from ...core.devices.registry import unlock_with_password
from ...core.flows.setup_machine import SetupFlow, SetupState
from ...core.flows.usb_setup import (
    SetupUsbError,
    discover_container,
    prepare_mountpoint,
)
from ...core.security.memory import SecretBytes
from ...core.security.password_strength import (
    MIN_LENGTH,
    estimate_password_strength,
)
from ...core.vault.kdbx import VaultHandle, VaultOpenError, open_vault
from ...core.vault.provisioning import (
    ProvisioningError,
    adopt_existing_vault,
    create_new_vault,
    read_vault_json,
)
from ...core.vaults.layout import VaultLayout
from ...core.vaults.registry import VaultRecord, add_vault
from ...integration.shortcuts import select_and_bind
from ...integration.usb.udisks2 import (
    Udisks2Unavailable,
    list_removable_drive_choices,
)
from ..widgets import (
    accelerator_display_label,
    build_brand_header,
    build_local_key_offer_content,
    build_step_dots,
)

APP_ID = "dev.ash.PasswordManager.Setup"
_STEP_COUNT = 6
_DEFAULT_HOTKEY = "<Control><Alt>p"
_HOTKEY_EXEC_CMD = "ash-password-manager sign-in"
_IGNORED_CAPTURE_KEYVALS = {
    Gdk.KEY_Control_L, Gdk.KEY_Control_R, Gdk.KEY_Alt_L, Gdk.KEY_Alt_R,
    Gdk.KEY_Shift_L, Gdk.KEY_Shift_R, Gdk.KEY_Super_L, Gdk.KEY_Super_R,
    Gdk.KEY_Meta_L, Gdk.KEY_Meta_R,
}


class SetupWindow(Adw.ApplicationWindow):
    def __init__(self, app: SetupApp) -> None:
        super().__init__(application=app, default_width=460, default_height=580, title="ASH Password Manager")
        self._flow = SetupFlow()
        self.result_handle: VaultHandle | None = None
        self.result_record: VaultRecord | None = None
        # Set instead of the two above when USB_SELECTION finds a USB
        # that is already a real ASH vault this device just doesn't
        # know about locally yet (a brand-new device, or "recover"):
        # this wizard's job becomes registering it in the local
        # registry and handing off to the LOGIN flow, not creating
        # anything -- see _on_usb_prepared's "ash" branch below.
        self.discovered_existing_vault: tuple[VaultRecord, str] | None = None

        self._selected_drive = None
        self._usb_identity = None
        self._mountpoint: str | None = None
        self._adopt_password_text: str = ""
        self._adopt_keyfile_rel: str | None = None
        self._master_password: SecretBytes | None = None
        self._hotkey_accelerator: str = _DEFAULT_HOTKEY
        self._recording_hotkey = False

        self._nav = Adw.NavigationView()
        self.set_content(self._nav)
        self._nav.push(self._build_usb_selection_page())

        key_controller = Gtk.EventControllerKey()
        key_controller.connect("key-pressed", self._on_hotkey_key_pressed)
        self.add_controller(key_controller)

    # -- shared page scaffold ---------------------------------------------

    def _page(self, title: str, step_index: int, body: Gtk.Widget) -> Adw.NavigationPage:
        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar(show_title=False))
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=16,
            margin_top=8, margin_bottom=24, margin_start=32, margin_end=32,
        )
        outer.append(build_step_dots(_STEP_COUNT, step_index))
        outer.append(body)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(outer)
        toolbar_view.set_content(scroller)
        return Adw.NavigationPage(title=title, child=toolbar_view)

    def _build_progress_page(self, message: str) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, valign=Gtk.Align.CENTER)
        box.append(Gtk.Spinner(spinning=True, width_request=32, height_request=32, halign=Gtk.Align.CENTER))
        box.append(Gtk.Label(label=message, xalign=0.5))
        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar(show_title=False))
        toolbar_view.set_content(box)
        return Adw.NavigationPage(title="Working…", child=toolbar_view)

    def _show_error(self, message: str) -> None:
        status = Adw.StatusPage(title="Something went wrong", description=message, icon_name="dialog-error-symbolic")
        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar(show_title=False))
        toolbar_view.set_content(status)
        self._nav.push(Adw.NavigationPage(title="Error", child=toolbar_view))

    # -- Step 1: USB selection ----------------------------------------------

    def _build_usb_selection_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.append(build_brand_header("Sign in"))
        box.append(Gtk.Label(label="Select your password USB", xalign=0.5))

        self._usb_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self._usb_list.add_css_class("boxed-list")
        box.append(self._usb_list)
        self._usb_status_label = Gtk.Label(xalign=0.5, wrap=True)
        box.append(self._usb_status_label)

        refresh_btn = Gtk.Button(label="Refresh")
        refresh_btn.connect("clicked", lambda _b: self._refresh_usb_list())
        box.append(refresh_btn)

        vault_name_group = Adw.PreferencesGroup()
        self._vault_name_row = Adw.EntryRow(title="Vault name")
        self._vault_name_row.set_text("My Passwords")
        vault_name_group.add(self._vault_name_row)
        box.append(vault_name_group)

        continue_btn = Gtk.Button(label="Continue", hexpand=True)
        continue_btn.add_css_class("suggested-action")
        continue_btn.connect("clicked", self._on_usb_selected)
        box.append(continue_btn)

        self._refresh_usb_list()
        return self._page("Sign in", 0, box)

    def _refresh_usb_list(self) -> None:
        while (row := self._usb_list.get_row_at_index(0)) is not None:
            self._usb_list.remove(row)
        try:
            choices = list_removable_drive_choices()
        except Udisks2Unavailable:
            self._usb_status_label.set_label("Could not detect removable drives on this system.")
            return
        if not choices:
            self._usb_status_label.set_label("No removable USB drives detected. Insert one and click Refresh.")
            return
        self._usb_status_label.set_label("")
        for choice in choices:
            row = Adw.ActionRow(title=choice.label)
            row.drive_choice = choice
            self._usb_list.append(row)
        self._usb_list.select_row(self._usb_list.get_row_at_index(0))

    def _on_usb_selected(self, _btn) -> None:
        row = self._usb_list.get_selected_row()
        if row is None:
            self._usb_status_label.set_label("Select a USB drive first.")
            return
        self._selected_drive = row.drive_choice
        self._flow.draft.vault_name = self._vault_name_row.get_text().strip() or "My Passwords"
        self._flow.advance_to(SetupState.USB_SELECTION)

        self._nav.push(self._build_progress_page("Preparing USB…"))
        run_blocking_async(self._prepare_usb_work, self._on_usb_prepared)

    def _prepare_usb_work(self):
        try:
            identity, mountpoint = prepare_mountpoint(
                self._selected_drive.object_path, self._selected_drive.vendor, self._selected_drive.model
            )
            # Scans for an existing vault at ANY container path on this
            # already-selected, already-mounted USB (spec section 14:
            # still never a generic file browser -- this is scoped to
            # the one USB the user just picked) -- not just the fixed
            # "ASH" default, so a vault created by an older flow (e.g.
            # a legacy single-vault registration's "Authentication/")
            # is still found automatically. See core.flows.usb_setup.
            container_rel_path, kind = discover_container(mountpoint)
            return identity, mountpoint, container_rel_path, kind, None
        except SetupUsbError as exc:
            return None, None, None, None, str(exc)

    def _on_usb_prepared(self, result) -> None:
        identity, mountpoint, container_rel_path, kind, error = result
        self._nav.pop()
        if error:
            self._usb_status_label.set_label(error)
            return
        self._usb_identity = identity
        self._mountpoint = mountpoint
        self._flow.draft.container_rel_path = container_rel_path
        if kind == "foreign":
            self._flow.advance_to(SetupState.ADOPT_OR_CREATE)
            self._nav.push(self._build_adopt_or_create_page())
        elif kind == "ash":
            self._nav.push(self._build_existing_vault_found_page())
        else:
            self._flow.draft.is_adoption = False
            self._flow.advance_to(SetupState.PASSWORD_CREATION)
            self._nav.push(self._build_password_page())

    # -- Step 1b: an ASH vault already exists here (new device / recover) ----

    def _build_existing_vault_found_page(self) -> Adw.NavigationPage:
        """Reached when the selected, already-mounted USB has a real
        ASH vault this *device* doesn't know about locally yet -- the
        exact "new device" / "recover" scenario (spec sections 5, 13),
        not a first-time setup. Registers the vault into this device's
        local registry (identity metadata only, no credential) and
        hands off to the normal Login flow, which will show the
        password prompt (no Local Key exists here yet) and, on
        success, offer to register this device with a brand-new key --
        never anything copied from another device."""
        layout = VaultLayout.at(self._mountpoint, self._flow.draft.container_rel_path)
        data = read_vault_json(layout) or {}
        vault_name = data.get("name") or self._flow.draft.vault_name

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.append(build_brand_header("Existing Vault Found"))
        box.append(
            Gtk.Label(
                label=f"This USB already has an ASH Password Manager vault named {vault_name!r}. "
                "This device isn't registered for it yet.",
                wrap=True, xalign=0.5,
            )
        )
        continue_btn = Gtk.Button(label="Continue to Login", hexpand=True)
        continue_btn.add_css_class("suggested-action")

        def on_continue(_btn) -> None:
            vault_id = data.get("vault_id")
            if not vault_id:
                self._show_error("Could not read this vault's identity (vault.json is missing or corrupt).")
                return
            record = VaultRecord(
                vault_id=vault_id,
                name=vault_name,
                luks_uuid=self._usb_identity.luks_uuid,
                filesystem_uuid=self._usb_identity.filesystem_uuid,
                drive_vendor=self._usb_identity.drive_vendor,
                drive_model=self._usb_identity.drive_model,
                container_rel_path=self._flow.draft.container_rel_path,
                label=vault_name,
            )
            add_vault(record)
            self.discovered_existing_vault = (record, self._mountpoint)
            self.close()

        continue_btn.connect("clicked", on_continue)
        box.append(continue_btn)
        self._existing_vault_continue_btn = continue_btn
        return self._page("Existing Vault", 0, box)

    # -- Step 1b (alternative): adopt-or-create a foreign KDBX --------------

    def _build_adopt_or_create_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.append(build_brand_header("Existing Password Database Found"))
        box.append(
            Gtk.Label(
                label="This USB already has a password database that isn't in ASH Password Manager's "
                "format. Adopt it to keep all its entries, or create a brand-new vault instead.",
                wrap=True, xalign=0.5,
            )
        )

        adopt_group = Adw.PreferencesGroup(title="Adopt Existing Database")
        self._adopt_password_row = Adw.PasswordEntryRow(title="Its current password (blank if key-file only)")
        adopt_group.add(self._adopt_password_row)
        self._adopt_keyfile_row = Adw.EntryRow(title="Its key file, relative to the USB root (optional)")
        adopt_group.add(self._adopt_keyfile_row)
        self._adopt_error = Gtk.Label(xalign=0, wrap=True)
        self._adopt_error.add_css_class("pm-error-label")
        self._adopt_error.set_visible(False)
        adopt_group.add(self._adopt_error)
        adopt_btn = Gtk.Button(label="Adopt This Database", hexpand=True)
        adopt_btn.connect("clicked", self._on_adopt_clicked)
        adopt_group.add(adopt_btn)
        box.append(adopt_group)

        create_btn = Gtk.Button(label="Create a New Vault Instead", hexpand=True)
        create_btn.add_css_class("suggested-action")
        create_btn.connect("clicked", self._on_create_new_instead_clicked)
        box.append(create_btn)
        return self._page("Existing Database", 0, box)

    def _on_adopt_clicked(self, _btn) -> None:
        self._flow.draft.is_adoption = True
        self._adopt_password_text = self._adopt_password_row.get_text()
        self._adopt_keyfile_rel = self._adopt_keyfile_row.get_text().strip() or None
        self._flow.advance_to(SetupState.PASSWORD_CREATION)
        self._nav.push(self._build_password_page())

    def _on_create_new_instead_clicked(self, _btn) -> None:
        self._flow.draft.is_adoption = False
        self._flow.draft.container_rel_path = "ASH"  # never touches the foreign KDBX left in place
        self._flow.advance_to(SetupState.PASSWORD_CREATION)
        self._nav.push(self._build_password_page())

    # -- Step 2: password creation --------------------------------------------

    def _build_password_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        title = "Confirm Your Password" if self._flow.draft.is_adoption else "Create Password"
        box.append(build_brand_header(title))
        if self._flow.draft.is_adoption:
            box.append(
                Gtk.Label(
                    label="This becomes your new ASH master password for the adopted vault.",
                    wrap=True, xalign=0.5,
                )
            )

        group = Adw.PreferencesGroup()
        self._password_row = Adw.PasswordEntryRow(title="Password")
        self._password_row.connect("notify::text", self._on_password_changed)
        group.add(self._password_row)
        self._confirm_row = Adw.PasswordEntryRow(title="Confirm Password")
        group.add(self._confirm_row)
        box.append(group)

        self._strength_label = Gtk.Label(xalign=0, label="Strength: --")
        box.append(self._strength_label)
        self._password_error = Gtk.Label(xalign=0, wrap=True)
        self._password_error.add_css_class("pm-error-label")
        self._password_error.set_visible(False)
        box.append(self._password_error)

        continue_btn = Gtk.Button(label="Continue", hexpand=True)
        continue_btn.add_css_class("suggested-action")
        continue_btn.connect("clicked", self._on_password_continue)
        box.append(continue_btn)
        return self._page("Create Password", 1, box)

    def _on_password_changed(self, *_a) -> None:
        strength = estimate_password_strength(self._password_row.get_text())
        self._strength_label.set_label(f"Strength: {strength.label}")

    def _on_password_continue(self, _btn) -> None:
        password = self._password_row.get_text()
        confirm = self._confirm_row.get_text()
        if len(password) < MIN_LENGTH:
            self._password_error.set_label(f"Password must be at least {MIN_LENGTH} characters.")
            self._password_error.set_visible(True)
            return
        if password != confirm:
            self._password_error.set_label("Passwords do not match.")
            self._password_error.set_visible(True)
            return
        self._password_error.set_visible(False)
        self._master_password = SecretBytes(password)
        self._flow.advance_to(SetupState.LOCAL_KEY_OPTIONAL)
        self._nav.push(self._build_local_key_page())

    # -- Step 3: local key optional, then commit the vault -------------------

    def _build_local_key_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.append(build_brand_header("Create Local Key"))
        box.append(
            Gtk.Label(label="Create a device key for passwordless login on this device?", wrap=True, xalign=0.5)
        )
        box.append(build_local_key_offer_content(self._on_skip_local_key, self._on_generate_local_key))
        return self._page("Local Key", 2, box)

    def _on_skip_local_key(self, _btn) -> None:
        self._flow.draft.enroll_local_key = False
        self._commit_vault()

    def _on_generate_local_key(self, _btn) -> None:
        self._flow.draft.enroll_local_key = True
        self._commit_vault()

    def _commit_vault(self) -> None:
        if self._flow.state is not SetupState.LOCAL_KEY_OPTIONAL:
            # Already committing (or already failed once and hasn't been
            # reset yet) -- ignore a duplicate Skip/Generate Key click
            # instead of crashing on an invalid state transition.
            return
        self._flow.advance_to(SetupState.VAULT_CREATION)
        self._flow.advance_to(SetupState.DEVICE_REGISTRATION)
        self._nav.push(self._build_progress_page("Creating your vault…"))
        run_blocking_async(self._commit_work, self._on_commit_done)

    def _commit_work(self):
        draft = self._flow.draft
        try:
            if draft.is_adoption:
                result = adopt_existing_vault(
                    self._mountpoint, draft.container_rel_path, draft.vault_name,
                    existing_password=SecretBytes(self._adopt_password_text) if self._adopt_password_text else None,
                    existing_keyfile_rel_path=self._adopt_keyfile_rel,
                    new_master_password=self._master_password,
                    enroll_local_key=draft.enroll_local_key,
                )
            else:
                result = create_new_vault(
                    self._mountpoint, draft.container_rel_path, draft.vault_name, self._master_password,
                    enroll_local_key=draft.enroll_local_key,
                )
        except ProvisioningError as exc:
            return None, str(exc)

        # self._master_password is untouched by provisioning (ownership
        # stays with the caller by design -- see core.crypto.keyslots)
        # so it can be reused immediately to derive VMS, exactly like a
        # normal password login, without re-prompting the user.
        vms = unlock_with_password(result.layout, self._master_password)
        self._master_password.wipe()
        self._master_password = None
        try:
            password_str = vms_to_kdbx_password(vms)
            handle = open_vault(result.layout.kdbx_path, result.layout.keyfile_path, SecretBytes(password_str))
        except VaultOpenError as exc:
            return None, f"Vault created but could not be reopened: {exc}"
        finally:
            vms.wipe()

        record = VaultRecord(
            vault_id=result.vault_id,
            name=draft.vault_name,
            luks_uuid=self._usb_identity.luks_uuid,
            filesystem_uuid=self._usb_identity.filesystem_uuid,
            drive_vendor=self._usb_identity.drive_vendor,
            drive_model=self._usb_identity.drive_model,
            container_rel_path=draft.container_rel_path,
            label=draft.vault_name,
        )
        add_vault(record)
        return (handle, record), None

    def _on_commit_done(self, result) -> None:
        payload, error = result
        self._nav.pop()
        if error:
            # create_new_vault/adopt_existing_vault guarantee zero
            # on-disk trace on failure (see provisioning.py) -- rewind
            # the in-memory wizard state to match, so the user can fix
            # the actual problem (e.g. an unwritable USB) and retry
            # from this same page instead of restarting the wizard.
            self._flow.state = SetupState.LOCAL_KEY_OPTIONAL
            self._show_error(error)
            return
        self.result_handle, self.result_record = payload
        self._flow.advance_to(SetupState.HOTKEY_SETUP)
        self._nav.push(self._build_hotkey_page())

    # -- Step 4: hotkey (vault already exists; this is a local setting) ------

    def _build_hotkey_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.append(build_brand_header("Open Manager Hotkey"))
        self._hotkey_label = Gtk.Label(label=accelerator_display_label(self._hotkey_accelerator), xalign=0.5)
        box.append(self._hotkey_label)

        record_btn = Gtk.Button(label="Record Different Shortcut...", hexpand=True)
        record_btn.connect("clicked", self._on_record_hotkey)
        box.append(record_btn)

        continue_btn = Gtk.Button(label="Continue", hexpand=True)
        continue_btn.add_css_class("suggested-action")
        continue_btn.connect("clicked", self._on_hotkey_continue)
        box.append(continue_btn)
        return self._page("Hotkey", 3, box)

    def _on_record_hotkey(self, _btn) -> None:
        self._recording_hotkey = True
        self._hotkey_label.set_label("Press a key combination…")

    def _on_hotkey_key_pressed(self, _controller, keyval, _keycode, state) -> bool:
        if not self._recording_hotkey:
            return False
        if keyval in _IGNORED_CAPTURE_KEYVALS:
            return True
        mods = state & Gtk.accelerator_get_default_mod_mask()
        if not Gtk.accelerator_valid(keyval, mods):
            return True
        self._hotkey_accelerator = Gtk.accelerator_name(keyval, mods)
        self._recording_hotkey = False
        self._hotkey_label.set_label(accelerator_display_label(self._hotkey_accelerator))
        return True

    def _on_hotkey_continue(self, _btn) -> None:
        self._flow.draft.hotkey_accelerator = self._hotkey_accelerator
        self._nav.push(self._build_progress_page("Applying shortcut…"))
        run_blocking_async(self._apply_hotkey_work, self._on_hotkey_applied)

    def _apply_hotkey_work(self):
        backend, outcome = select_and_bind(self._hotkey_accelerator, _HOTKEY_EXEC_CMD, "Open ASH Password Manager")
        return backend.name if outcome.result.value == "ok" else None

    def _on_hotkey_applied(self, backend_name: str | None) -> None:
        self._nav.pop()
        s = load_settings()
        s.hotkey_accelerator = self._hotkey_accelerator
        s.hotkey_backend = backend_name or ""
        save_settings(s)
        self._flow.advance_to(SetupState.USB_REMOVAL_CONFIGURATION)
        self._nav.push(self._build_usb_removal_explanation_page())

    # -- Step 5: USB removal (explanation, then choice) -----------------------

    def _build_usb_removal_explanation_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.append(build_brand_header("USB Removal Protection"))
        box.append(
            Gtk.Label(
                label="Your password vault is stored on the USB. When the USB is removed, ASH Password "
                "Manager can automatically lock the manager to reduce the risk of leaving the vault "
                "unlocked.\n\nThis setting can be changed later in Settings.",
                wrap=True, xalign=0.5,
            )
        )
        continue_btn = Gtk.Button(label="Continue", hexpand=True)
        continue_btn.add_css_class("suggested-action")
        continue_btn.connect("clicked", lambda _b: self._nav.push(self._build_usb_removal_choice_page()))
        box.append(continue_btn)
        return self._page("USB Removal", 4, box)

    def _build_usb_removal_choice_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.append(build_brand_header("When USB Is Removed"))

        lock_row = Gtk.CheckButton(label="Lock immediately")
        keep_row = Gtk.CheckButton(label="Keep unlocked", group=lock_row)
        lock_row.set_active(True)
        box.append(lock_row)
        box.append(keep_row)
        self._usb_removal_lock_row = lock_row

        finish_btn = Gtk.Button(label="Finish Setup", hexpand=True)
        finish_btn.add_css_class("suggested-action")
        finish_btn.connect("clicked", self._on_finish_setup)
        box.append(finish_btn)
        return self._page("USB Removal", 5, box)

    def _on_finish_setup(self, _btn) -> None:
        action = "lock_immediately" if self._usb_removal_lock_row.get_active() else "keep_unlocked"
        s = load_settings()
        s.usb_removal_action = action
        s.usb_removal_explained = True
        save_settings(s)
        self._flow.advance_to(SetupState.SETUP_COMPLETE)
        self.close()


class SetupApp(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.result_handle: VaultHandle | None = None
        self.result_record: VaultRecord | None = None
        self.result_mountpoint: str | None = None
        self.discovered_existing_vault: tuple[VaultRecord, str] | None = None
        self._window: SetupWindow | None = None

    def do_activate(self) -> None:
        # GApplication re-invokes do_activate() for every "activate",
        # including one relayed over D-Bus from a second process
        # invocation while this one is already running (its own single-
        # instance mechanism -- separate from launcher.ipc's) --
        # confirmed live: running `ash-password-manager sign-in` again
        # while a Setup window was already open silently created a
        # second, independent window on the same process instead of
        # focusing the first, with the second CLI invocation itself
        # returning immediately (looking, from the terminal, like
        # nothing happened). Mirrors PasswordManagerApp.do_activate's
        # existing, already-correct guard exactly.
        if self._window is None:
            self._window = SetupWindow(self)
            self._window.connect("close-request", self._on_window_closed)
        self._window.present()

    def _on_window_closed(self, window: SetupWindow) -> bool:
        self.result_handle = window.result_handle
        self.result_record = window.result_record
        self.result_mountpoint = window._mountpoint
        self.discovered_existing_vault = window.discovered_existing_vault
        GLib.idle_add(self.quit)
        return False


def run_setup_wizard() -> tuple[VaultHandle | None, VaultRecord | None, str | None, tuple[VaultRecord, str] | None]:
    """Returns ``(handle, record, mountpoint, discovered_existing_vault)``.

    Normal completion (a new vault was created, or a foreign KDBX was
    adopted) sets the first three and leaves the fourth ``None``.
    Finding an *existing* ASH vault this device isn't registered for
    yet (spec sections 5, 13 -- a new device, or "recover") instead
    sets only ``discovered_existing_vault`` to ``(record, mountpoint)``
    -- nothing was created, so the caller should proceed to the normal
    Login flow with that record/mountpoint, not treat it as a fresh
    vault. The user closing the wizard before completing anything
    returns all four as ``None``."""
    app = SetupApp()
    app.run(None)
    return app.result_handle, app.result_record, app.result_mountpoint, app.discovered_existing_vault
