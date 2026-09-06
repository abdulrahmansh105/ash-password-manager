"""ASH Password Manager's main window (spec section 23): search,
category sidebar, and the entry list -- the day-to-day password
manager UI shown after a successful unlock.

Deliberately separate from ``ui.launcher_window.AccountPickerWindow``,
which remains the fast SUPER+CTRL+A autotype picker from the original
design (spec section 34 decision: autotype stays a fully-working
advanced feature, reachable from an entry's detail view and Settings
-> Authentication, never the primary Sign in/Login/Manager flow).

Both windows share the same underlying vault/session/dialog machinery
-- ``AccountDetailDialog``, ``EntryEditorDialog``, ``GeneratorDialog``,
``SettingsDialog``, ``core.accounts.repository`` -- none of it is
duplicated here. This window is the one ``PasswordManagerApp`` opens
when it was started through the new login flow (``ui.login`` passes
``unlocked_vault=...``, see ``ui/app.py``); autotype for a given entry
is one action away in ``AccountDetailDialog``'s "Authentication Flow"
section, which already exists and is unchanged.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from ...core.accounts.repository import search as search_accounts
from ...core.security.session import LockReason
from ...core.vault.models import CATEGORY_LABELS
from ..account_detail import AccountDetailDialog
from ..entry_editor import EntryEditorDialog
from ..generator_view import GeneratorDialog
from ..settings_window import SettingsDialog

ALL_CATEGORY_KEY = "all"
_SIDEBAR_ITEMS = [(ALL_CATEGORY_KEY, "All")] + list(CATEGORY_LABELS.items())
_CATEGORY_ICONS = {
    "logins": "dialog-password-symbolic",
    "software": "application-x-executable-symbolic",
    "wifi": "network-wireless-symbolic",
    "secure_notes": "text-x-generic-symbolic",
    "other": "folder-symbolic",
}


class _EntryRow(Adw.ActionRow):
    def __init__(self, summary) -> None:
        super().__init__(
            title=GLib.markup_escape_text(summary.display_name),
            subtitle=GLib.markup_escape_text(summary.service_name or ""),
            activatable=True,
        )
        self.summary = summary
        icon = Gtk.Image.new_from_icon_name(_CATEGORY_ICONS.get(summary.category, "dialog-password-symbolic"))
        icon.set_pixel_size(28)
        self.add_prefix(icon)
        chevron = Gtk.Image.new_from_icon_name("go-next-symbolic")
        chevron.add_css_class("dim-label")
        self.add_suffix(chevron)


class _CategoryRow(Adw.ActionRow):
    def __init__(self, key: str, label: str) -> None:
        super().__init__(title=label)
        self.category_key = key


class ManagerWindow(Adw.ApplicationWindow):
    def __init__(self, app) -> None:
        super().__init__(application=app, default_width=780, default_height=560, title="ASH Password Manager")
        self.app = app
        self._selected_category = ALL_CATEGORY_KEY
        self._all_summaries: list = []

        self._toast_overlay = Adw.ToastOverlay()
        self.set_content(self._toast_overlay)

        split_view = Adw.NavigationSplitView(min_sidebar_width=190, max_sidebar_width=260)
        self._toast_overlay.set_child(split_view)

        split_view.set_sidebar(Adw.NavigationPage(title="Categories", child=self._build_sidebar()))
        split_view.set_content(Adw.NavigationPage(title="Passwords", child=self._build_content()))

        self._category_list.select_row(self._category_list.get_row_at_index(0))
        self.refresh_accounts()
        self._search_entry.grab_focus()

        activity = Gtk.EventControllerMotion()
        activity.connect("motion", lambda *_: self.app.session.touch_activity())
        self.add_controller(activity)
        key_activity = Gtk.EventControllerKey()
        key_activity.connect("key-pressed", lambda *_: (self.app.session.touch_activity(), False)[1])
        self.add_controller(key_activity)

    # -- construction ----------------------------------------------------

    def _build_sidebar(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        header = Adw.HeaderBar(show_end_title_buttons=False)
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, spacing=0)
        brand = Gtk.Label(label="ASH Password Manager", xalign=0)
        brand.add_css_class("ash-brand-title")
        brand.add_css_class("title-4")
        title_box.append(brand)
        header.set_title_widget(title_box)
        box.append(header)

        self._category_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self._category_list.add_css_class("navigation-sidebar")
        for key, label in _SIDEBAR_ITEMS:
            self._category_list.append(_CategoryRow(key, label))
        self._category_list.connect("row-selected", self._on_category_selected)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(self._category_list)
        box.append(scroller)

        lock_btn = Gtk.Button(label="Lock Vault", margin_start=8, margin_end=8, margin_bottom=8, margin_top=4)
        lock_btn.add_css_class("flat")
        lock_btn.connect("clicked", lambda _b: self.app.session.lock(LockReason.MANUAL_CLOSE))
        box.append(lock_btn)
        return box

    def _build_content(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        header = Adw.HeaderBar()
        self._search_entry = Gtk.SearchEntry(placeholder_text="Search passwords...")
        self._search_entry.connect("search-changed", lambda _e: self._refresh_list())
        header.set_title_widget(self._search_entry)

        add_btn = Gtk.Button.new_from_icon_name("list-add-symbolic")
        add_btn.set_tooltip_text("Add entry")
        add_btn.connect("clicked", self._on_add)
        header.pack_start(add_btn)

        settings_btn = Gtk.Button.new_from_icon_name("emblem-system-symbolic")
        settings_btn.set_tooltip_text("Settings")
        settings_btn.connect("clicked", lambda _b: SettingsDialog(self.app).present(self))
        header.pack_end(settings_btn)

        gen_btn = Gtk.Button.new_from_icon_name("dialog-password-symbolic")
        gen_btn.set_tooltip_text("Password generator")
        gen_btn.connect("clicked", lambda _b: GeneratorDialog(self).present(self))
        header.pack_end(gen_btn)

        box.append(header)

        self._content_stack = Gtk.Stack()
        self._entry_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self._entry_list.add_css_class("boxed-list")
        self._entry_list.set_margin_start(12)
        self._entry_list.set_margin_end(12)
        self._entry_list.set_margin_top(12)
        self._entry_list.set_margin_bottom(12)
        self._entry_list.connect("row-activated", self._on_row_activated)
        list_scroller = Gtk.ScrolledWindow(vexpand=True)
        list_scroller.set_child(self._entry_list)
        self._content_stack.add_named(list_scroller, "list")

        empty_status = Adw.StatusPage(
            title="No entries yet",
            description="Add your first password with the + button above.",
            icon_name="dialog-password-symbolic",
        )
        self._content_stack.add_named(empty_status, "empty")

        box.append(self._content_stack)
        return box

    # -- data --------------------------------------------------------------

    def refresh_accounts(self) -> None:
        if not self.app.session.is_unlocked():
            return
        vault = self.app.session.vault()
        self._all_summaries = vault.list_account_summaries()
        self._refresh_list()

    def _on_category_selected(self, _box, row) -> None:
        if row is None:
            return
        self._selected_category = row.category_key
        self._refresh_list()

    def _refresh_list(self) -> None:
        query = self._search_entry.get_text()
        matches = search_accounts(self._all_summaries, query)
        if self._selected_category != ALL_CATEGORY_KEY:
            matches = [m for m in matches if m.category == self._selected_category]
        matches = sorted(matches, key=lambda s: s.display_name.lower())

        while (child := self._entry_list.get_row_at_index(0)) is not None:
            self._entry_list.remove(child)
        for summary in matches:
            self._entry_list.append(_EntryRow(summary))

        self._content_stack.set_visible_child_name("list" if matches else "empty")

    # -- actions -------------------------------------------------------------

    def _on_row_activated(self, _box, row: _EntryRow) -> None:
        AccountDetailDialog(self.app, row.summary.entry_uuid, on_changed=self.refresh_accounts).present(self)

    def _on_add(self, _btn) -> None:
        EntryEditorDialog(self.app, on_saved=self.refresh_accounts).present(self)

    # -- lock teardown (spec section 11/25: clear sensitive UI state) --------

    def destroy_sensitive_state(self) -> None:
        while (child := self._entry_list.get_row_at_index(0)) is not None:
            self._entry_list.remove(child)
        self._all_summaries = []
        self._search_entry.set_text("")
