"""Main vault manager: click an entry to confirm Auto-Type; use its
details button to view/edit the account. Search, categories, and dialogs
share the existing vault and session machinery with the legacy picker.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk

from ...core.accounts.repository import search as search_accounts
from ...core.security.session import LockReason
from ...core.vault.models import CATEGORY_LABELS
from ..account_detail import AccountDetailDialog
from ..autotype import request_autotype
from ..entry_editor import EntryEditorDialog
from ..generator_view import GeneratorDialog
from ..settings_window import SettingsDialog
from ..widgets import icon_button, style_window

ALL_CATEGORY_KEY = "all"
_SIDEBAR_ITEMS = [(ALL_CATEGORY_KEY, "All entries")] + list(CATEGORY_LABELS.items())
_CATEGORY_ICONS = {
    "logins": "dialog-password-symbolic",
    "software": "application-x-executable-symbolic",
    "wifi": "network-wireless-symbolic",
    "secure_notes": "text-x-generic-symbolic",
    "other": "folder-symbolic",
}


class _EntryRow(Adw.ActionRow):
    def __init__(self, summary, on_details) -> None:
        super().__init__(
            title=GLib.markup_escape_text(summary.display_name),
            subtitle=GLib.markup_escape_text(summary.service_name or ""),
            activatable=True,
        )
        self.summary = summary
        self.add_css_class("pm-account-row")
        self.set_title_lines(1)
        self.set_subtitle_lines(1)
        icon = Gtk.Image.new_from_icon_name(_CATEGORY_ICONS.get(summary.category, "dialog-password-symbolic"))
        icon.set_pixel_size(24)
        icon.add_css_class("pm-account-icon")
        self.add_prefix(icon)
        if summary.has_totp:
            badge = Gtk.Image.new_from_icon_name("channel-secure-symbolic")
            badge.set_tooltip_text("Authenticator configured")
            self.add_suffix(badge)
        details = icon_button("dialog-information-symbolic", "Account details / edit", lambda _b: on_details(summary))
        details.set_valign(Gtk.Align.CENTER)
        self.add_suffix(details)
        self.set_tooltip_text("Click to Auto-Type · details button to view or edit")


class _CategoryRow(Adw.ActionRow):
    def __init__(self, key: str, label: str) -> None:
        super().__init__(title=label)
        self.category_key = key
        self.add_css_class("pm-category-row")
        self.add_prefix(Gtk.Image.new_from_icon_name(_CATEGORY_ICONS.get(key, "view-grid-symbolic")))
        self.count = Gtk.Label(label="0")
        self.count.add_css_class("pm-count")
        self.add_suffix(self.count)


class ManagerWindow(Adw.ApplicationWindow):
    def __init__(self, app) -> None:
        super().__init__(application=app, default_width=980, default_height=700, title="ASH Password Manager")
        self.app = app
        style_window(self, app.settings)
        self.set_size_request(360, 360)
        self._selected_category = ALL_CATEGORY_KEY
        self._all_summaries: list = []

        self._toast_overlay = Adw.ToastOverlay()
        self.set_content(self._toast_overlay)

        split_view = Adw.NavigationSplitView(min_sidebar_width=220, max_sidebar_width=250)
        self._split_view = split_view
        self._toast_overlay.set_child(split_view)

        split_view.set_sidebar(Adw.NavigationPage(title="Categories", child=self._build_sidebar()))
        split_view.set_content(Adw.NavigationPage(title="Passwords", child=self._build_content()))

        breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 720px"))
        breakpoint.add_setter(split_view, "collapsed", True)
        self.add_breakpoint(breakpoint)
        split_view.set_show_content(True)

        self._category_list.select_row(self._category_list.get_row_at_index(0))
        self.refresh_accounts()
        self._search_entry.grab_focus()

        activity = Gtk.EventControllerMotion()
        activity.connect("motion", lambda *_: self.app.session.touch_activity())
        self.add_controller(activity)
        key_activity = Gtk.EventControllerKey()
        key_activity.connect("key-pressed", self._on_key_pressed)
        self.add_controller(key_activity)

    # -- construction ----------------------------------------------------

    def _build_sidebar(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.add_css_class("pm-sidebar")
        header = Adw.HeaderBar(show_end_title_buttons=False)
        header.set_title_widget(Gtk.Label(label="ASH", css_classes=["ash-brand-title", "title-2"]))
        box.append(header)
        caption = Gtk.Label(label="YOUR VAULT", xalign=0, margin_start=24, margin_top=24, margin_bottom=8)
        caption.add_css_class("pm-eyebrow")
        box.append(caption)
        self._category_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self._category_list.add_css_class("navigation-sidebar")
        for key, label in _SIDEBAR_ITEMS:
            self._category_list.append(_CategoryRow(key, label))
        self._category_list.connect("row-selected", self._on_category_selected)
        scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(self._category_list)
        box.append(scroller)
        tools = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_start=16, margin_end=16, margin_bottom=20)
        for label, callback in (
            ("Password generator", lambda _b: GeneratorDialog(self).present(self)),
            ("Settings", lambda _b: SettingsDialog(self.app).present(self)),
            ("Lock vault", lambda _b: self.app.session.lock(LockReason.MANUAL_CLOSE)),
        ):
            button = Gtk.Button(label=label)
            button.set_halign(Gtk.Align.FILL)
            button.add_css_class("flat")
            button.connect("clicked", callback)
            tools.append(button)
        box.append(tools)
        return box

    def _build_content(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        header = Adw.HeaderBar()
        header.set_title_widget(Gtk.Label(label="Password Manager", css_classes=["dim-label"]))
        header.pack_end(icon_button("changes-prevent-symbolic", "Lock vault · Ctrl+L", lambda _b: self.app.session.lock(LockReason.MANUAL_CLOSE)))
        box.append(header)

        intro = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, margin_start=24, margin_end=24, margin_top=20, margin_bottom=20)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True)
        self._category_title = Gtk.Label(label="All entries", xalign=0)
        self._category_title.add_css_class("pm-page-heading")
        self._result_count = Gtk.Label(xalign=0)
        self._result_count.add_css_class("pm-subtitle")
        text.append(self._category_title)
        text.append(self._result_count)
        intro.append(text)
        add_btn = Gtk.Button(label="Add entry", valign=Gtk.Align.CENTER)
        add_btn.add_css_class("suggested-action")
        add_btn.add_css_class("pm-primary")
        add_btn.set_tooltip_text("Add entry · Ctrl+N")
        add_btn.connect("clicked", self._on_add)
        intro.append(add_btn)
        box.append(intro)

        self._search_entry = Gtk.SearchEntry(placeholder_text="Search by account or service…", margin_start=24, margin_end=24, margin_bottom=16)
        self._search_entry.set_hexpand(True)
        self._search_entry.set_tooltip_text("Search entries · Ctrl+F")
        self._search_entry.connect("search-changed", lambda _e: self._refresh_list())
        self._search_entry.connect("activate", self._on_search_activate)
        box.append(self._search_entry)
        self._content_stack = Gtk.Stack(vexpand=True)
        self._entry_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, valign=Gtk.Align.START)
        self._entry_list.add_css_class("boxed-list")
        self._entry_list.set_margin_start(24)
        self._entry_list.set_margin_end(24)
        self._entry_list.set_margin_bottom(24)
        self._entry_list.connect("row-activated", self._on_row_activated)
        list_scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        list_scroller.set_child(self._entry_list)
        self._content_stack.add_named(list_scroller, "list")
        self._empty_status = Adw.StatusPage(icon_name="dialog-password-symbolic")
        self._empty_action = Gtk.Button(label="Add your first entry", halign=Gtk.Align.CENTER)
        self._empty_action.add_css_class("suggested-action")
        self._empty_action.add_css_class("pm-primary")
        self._empty_action.connect("clicked", self._on_empty_action)
        self._empty_status.set_child(self._empty_action)
        self._content_stack.add_named(self._empty_status, "empty")
        box.append(self._content_stack)
        footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        footer.add_css_class("pm-footer")
        footer.append(Gtk.Image.new_from_icon_name("channel-secure-symbolic"))
        label = Gtk.Label(label="Vault unlocked", xalign=0, hexpand=True)
        label.add_css_class("pm-hint-label")
        footer.append(label)
        hint = Gtk.Label(label="Click entry: Auto-Type · ⓘ Details · Ctrl+F Search")
        hint.set_wrap(True)
        hint.set_xalign(1)
        hint.add_css_class("pm-hint-label")
        footer.append(hint)
        box.append(footer)
        return box

    def _on_empty_action(self, _button) -> None:
        if self._search_entry.get_text().strip():
            self._search_entry.set_text("")
            self._search_entry.grab_focus()
        else:
            self._on_add(None)

    def _on_search_activate(self, _entry) -> None:
        row = self._entry_list.get_row_at_index(0)
        if row is not None:
            self._on_row_activated(self._entry_list, row)

    def _on_key_pressed(self, _controller, keyval, _keycode, state) -> bool:
        self.app.session.touch_activity()
        if state & Gdk.ModifierType.CONTROL_MASK:
            if keyval in (Gdk.KEY_f, Gdk.KEY_F):
                self._search_entry.grab_focus()
                return True
            if keyval in (Gdk.KEY_n, Gdk.KEY_N):
                self._on_add(None)
                return True
            if keyval in (Gdk.KEY_l, Gdk.KEY_L):
                self.app.session.lock(LockReason.MANUAL_CLOSE)
                return True
        return False

    # -- data --------------------------------------------------------------

    def refresh_accounts(self) -> None:
        if not self.app.session.is_unlocked():
            return
        vault = self.app.session.vault()
        self._all_summaries = vault.list_account_summaries()
        for index, (key, _label) in enumerate(_SIDEBAR_ITEMS):
            count = len(self._all_summaries) if key == ALL_CATEGORY_KEY else sum(s.category == key for s in self._all_summaries)
            self._category_list.get_row_at_index(index).count.set_text(str(count))
        self._refresh_list()

    def _on_category_selected(self, _box, row) -> None:
        if row is None:
            return
        self._selected_category = row.category_key
        self._split_view.set_show_content(True)
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
            self._entry_list.append(_EntryRow(summary, self._on_details))

        self._category_title.set_text(dict(_SIDEBAR_ITEMS)[self._selected_category])
        count = len(matches)
        self._result_count.set_text(f"{count} {'result' if count == 1 else 'results'}" if query.strip() else f"{count} {'entry' if count == 1 else 'entries'} in your vault")
        if query.strip():
            self._empty_status.set_title("No matching entries")
            self._empty_status.set_description("Try another account or service name, or clear your search.")
            self._empty_action.set_label("Clear search")
        elif self._selected_category != ALL_CATEGORY_KEY:
            self._empty_status.set_title("This category is empty")
            self._empty_status.set_description("Add an entry to keep everything organised.")
            self._empty_action.set_label("Add entry")
        else:
            self._empty_status.set_title("Your vault starts here")
            self._empty_status.set_description("Keep your passwords, notes and recovery codes together.")
            self._empty_action.set_label("Add your first entry")
        self._content_stack.set_visible_child_name("list" if matches else "empty")

    # -- actions -------------------------------------------------------------

    def _on_row_activated(self, _box, row: _EntryRow) -> None:
        request_autotype(self.app, self, row.summary.entry_uuid, row.summary.display_name)

    def _on_details(self, summary) -> None:
        AccountDetailDialog(self.app, summary.entry_uuid, on_changed=self.refresh_accounts).present(self)

    def _on_add(self, _btn) -> None:
        EntryEditorDialog(self.app, on_saved=self.refresh_accounts).present(self)

    # -- lock teardown (spec section 11/25: clear sensitive UI state) --------

    def destroy_sensitive_state(self) -> None:
        while (child := self._entry_list.get_row_at_index(0)) is not None:
            self._entry_list.remove(child)
        self._all_summaries = []
        self._search_entry.set_text("")
        self._result_count.set_text("")
        for index in range(len(_SIDEBAR_ITEMS)):
            self._category_list.get_row_at_index(index).count.set_text("0")
