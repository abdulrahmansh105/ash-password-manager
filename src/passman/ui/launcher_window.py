"""The account picker -- the primary experience (spec sections 7-11).

A vertical menu/list, one account per row, keyboard-first search, a
"Suggested" section that ranks but never filters, and a Safety-Guard-
gated full sign-in on activation. Deliberately styled and driven like an
application launcher / command palette (``Gtk.ListBox`` + arrow-key
navigation), not a card grid: no ``Gtk.FlowBox``, no card chrome. No
animations (``gtk-enable-animations`` is disabled app-wide; nothing here
uses ``Gtk.Revealer``/eased transitions).

Full sign-in execution never runs on this (GTK main) thread -- see
``core.auth.async_login`` for why and how; this window only ever hands
work off to ``run_login_async`` and receives a result back via a
callback GLib has already marshalled onto the main thread.
"""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from ..core.accounts.repository import rank_by_context, search, suggested_and_other
from ..core.auth.async_login import run_login_async
from ..core.auth.engine import (
    GuardDecision,
    LoginOutcome,
    SafetyGuardMode,
    confidence_for_account,
    evaluate_safety_guard,
)
from ..core.auth.strategy import AuthStrategy
from ..core.security.logging import get_logger, safe_extra
from ..core.vault.models import AccountSummary
from ..input import select_backend
from .account_detail import AccountDetailDialog
from .entry_editor import EntryEditorDialog, TotpSetupDialog
from .generator_view import GeneratorDialog
from .settings_window import SettingsDialog

_log = get_logger(__name__)

_ICON_SIZE = 28


class AccountRow(Adw.ActionRow):
    """One menu row: a fixed-size site icon, the custom account name as
    the primary label, and the service name as a subtle secondary
    label -- never username/email/password/TOTP/recovery codes.
    ``Adw.ActionRow`` (inside a ``Gtk.ListBox``) is used deliberately
    instead of a bespoke widget: it already gives correct keyboard
    activation, an accessible name/description pair, and a suffix slot
    for the TOTP-add button that -- exactly like a suffix button on any
    other ``Adw.ActionRow`` -- takes its own click without also firing
    the row's ``activated`` signal, so no nested-``Gtk.Button`` ambiguity
    to work around here."""

    def __init__(
        self,
        summary: AccountSummary,
        mountpoint: str,
        on_secondary=None,
        on_add_totp=None,
    ) -> None:
        super().__init__(
            title=GLib.markup_escape_text(summary.display_name),
            subtitle=GLib.markup_escape_text(summary.service_name),
        )
        self.summary = summary
        self.set_activatable(True)
        self.add_css_class("pm-account-row")
        self.set_title_lines(1)
        self.set_subtitle_lines(1)

        if on_secondary is not None:
            right_click = Gtk.GestureClick(button=3)
            right_click.connect("released", lambda *_: on_secondary(summary))
            self.add_controller(right_click)

        icon = Gtk.Image()
        icon.set_pixel_size(_ICON_SIZE)
        icon.add_css_class("pm-account-icon")
        icon_path = None
        if summary.icon_ref:
            candidate = Path(mountpoint) / "icons" / summary.icon_ref
            if candidate.exists():
                icon_path = candidate
        if icon_path:
            icon.set_from_file(str(icon_path))
        else:
            icon.set_from_icon_name("dialog-password-symbolic")
        self.add_prefix(icon)

        if summary.has_totp:
            totp_icon = Gtk.Image.new_from_icon_name("changes-prevent-symbolic")
            totp_icon.set_tooltip_text("TOTP configured")
            totp_icon.set_valign(Gtk.Align.CENTER)
            self.add_suffix(totp_icon)
        elif on_add_totp is not None:
            add_totp_btn = Gtk.Button.new_from_icon_name("list-add-symbolic")
            add_totp_btn.add_css_class("flat")
            add_totp_btn.add_css_class("circular")
            add_totp_btn.set_valign(Gtk.Align.CENTER)
            add_totp_btn.set_tooltip_text("Add TOTP")
            add_totp_btn.connect("clicked", lambda _b: on_add_totp(summary))
            self.add_suffix(add_totp_btn)


def _make_header_row(text: str) -> Gtk.ListBoxRow:
    """A non-interactive section divider ("Suggested" / "Other
    accounts") inside the same ``Gtk.ListBox`` as the account rows.
    Marked unselectable/unactivatable/unfocusable so it never becomes a
    keyboard-navigation stop and never highlights on hover -- Up/Down
    moves between account rows only, skipping straight over these."""
    row = Gtk.ListBoxRow()
    row.set_selectable(False)
    row.set_activatable(False)
    row.set_focusable(False)
    row.add_css_class("pm-menu-header")
    label = Gtk.Label(label=text, xalign=0)
    label.add_css_class("pm-section-label")
    label.set_margin_top(10)
    label.set_margin_bottom(4)
    label.set_margin_start(12)
    label.set_margin_end(12)
    row.set_child(label)
    return row


class AccountPickerWindow(Adw.ApplicationWindow):
    def __init__(self, app) -> None:
        super().__init__(application=app, default_width=500, default_height=580)
        self.app = app
        self._all_accounts: list[AccountSummary] = []
        self._app_ids_by_uuid: dict[str, tuple[str, ...]] = {}
        self._nav_rows: list[AccountRow] = []
        self._selected_index: int = -1

        self._toast_overlay = Adw.ToastOverlay()
        self.set_content(self._toast_overlay)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._toast_overlay.set_child(root)

        header = Adw.HeaderBar()
        self._search_entry = Gtk.SearchEntry(placeholder_text="Search accounts...")
        self._search_entry.connect("search-changed", self._on_search_changed)
        self._search_entry.connect("activate", self._on_search_activate)
        header.set_title_widget(self._search_entry)

        add_button = Gtk.Button.new_from_icon_name("list-add-symbolic")
        add_button.set_tooltip_text("Add account")
        add_button.connect("clicked", self._on_add_account)
        header.pack_start(add_button)

        gen_button = Gtk.Button.new_from_icon_name("dialog-password-symbolic")
        gen_button.set_tooltip_text("Password generator")
        gen_button.connect("clicked", self._on_open_generator)
        header.pack_end(gen_button)

        settings_button = Gtk.Button.new_from_icon_name("emblem-system-symbolic")
        settings_button.set_tooltip_text("Settings")
        settings_button.connect("clicked", self._on_open_settings)
        header.pack_end(settings_button)

        root.append(header)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self._scroller = scroller
        self._menu = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self._menu.add_css_class("pm-account-menu")
        self._menu.set_activate_on_single_click(True)
        self._menu.connect("row-activated", self._on_row_activated)
        scroller.set_child(self._menu)
        root.append(scroller)

        self._empty_label = Gtk.Label(label="No accounts found", xalign=0.5)
        self._empty_label.add_css_class("pm-hint-label")
        self._empty_label.set_margin_top(24)
        self._empty_label.set_visible(False)
        root.append(self._empty_label)

        # Confirmation banner for the Safety Guard -- shown only when a
        # target's confidence isn't high enough to auto-proceed.
        self._confirm_bar = Adw.Banner()
        self._confirm_bar.set_revealed(False)
        root.append(self._confirm_bar)

        key_controller = Gtk.EventControllerKey()
        key_controller.connect("key-pressed", self._on_key_pressed)
        self.add_controller(key_controller)

        self.refresh_accounts()
        self._search_entry.grab_focus()

    # -- data -----------------------------------------------------------

    def refresh_accounts(self) -> None:
        vault = self.app.session.vault()
        self._all_accounts = vault.list_account_summaries()
        self._app_ids_by_uuid = {}
        for a in self._all_accounts:
            secrets = vault.get_account_secrets(a.entry_uuid)
            try:
                self._app_ids_by_uuid[a.entry_uuid] = secrets.app_identifiers
            finally:
                secrets.wipe()
        self._render(self._all_accounts)

    def _render(self, accounts: list[AccountSummary]) -> None:
        # Uses the context captured once at shortcut-press time
        # (app.detected_context, set by launcher.daemon.run_show()
        # before this window ever existed) -- never re-queried here,
        # since by now this window itself is what's focused.
        context = self.app.detected_context if self.app.settings.suggested_account_enabled else None
        if context is not None:
            ranked = rank_by_context(accounts, context, self._app_ids_by_uuid)
            suggested, other = suggested_and_other(ranked)
        else:
            suggested, other = [], accounts

        self._fill_menu(suggested, other)

    def _fill_menu(self, suggested: list[AccountSummary], other: list[AccountSummary]) -> None:
        child = self._menu.get_row_at_index(0)
        while child is not None:
            self._menu.remove(child)
            child = self._menu.get_row_at_index(0)
        self._nav_rows = []

        if suggested:
            self._menu.append(_make_header_row("Suggested"))
            for summary in suggested:
                self._append_row(summary)
        if other:
            self._menu.append(_make_header_row("Other accounts"))
            for summary in other:
                self._append_row(summary)

        self._empty_label.set_visible(not self._nav_rows)
        self._menu.set_visible(bool(self._nav_rows))
        self._select_index(0 if self._nav_rows else -1)

    def _append_row(self, summary: AccountSummary) -> None:
        row = AccountRow(
            summary,
            self.app.mountpoint,
            self._on_account_secondary,
            self._on_add_totp,
        )
        self._menu.append(row)
        self._nav_rows.append(row)

    def _on_account_secondary(self, summary: AccountSummary) -> None:
        AccountDetailDialog(self.app, summary.entry_uuid, on_changed=self.refresh_accounts).present(self)

    def _on_add_totp(self, summary: AccountSummary) -> None:
        def on_configured(config) -> None:
            vault = self.app.session.vault()
            vault.set_totp(summary.entry_uuid, config, issuer=summary.service_name)
            vault.save()
            self.refresh_accounts()

        TotpSetupDialog(on_configured).present(self)

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        query = entry.get_text()
        results = search(self._all_accounts, query)
        self._render(results)

    # -- keyboard-first navigation ----------------------------------------
    # Selection is tracked explicitly over ``self._nav_rows`` (account
    # rows only -- section headers are never in this list) rather than
    # relying on GtkListBox's own cursor movement, so Up/Down/Enter/Escape
    # behavior here is exact and independent of GTK version quirks.
    # Keyboard focus deliberately stays in the search entry throughout --
    # only the row's selection highlight moves -- so typing always
    # continues to search immediately, mid-navigation.

    def _select_index(self, index: int) -> None:
        if not self._nav_rows or not (0 <= index < len(self._nav_rows)):
            self._selected_index = -1
            self._menu.unselect_all()
            return
        self._selected_index = index
        row = self._nav_rows[index]
        self._menu.select_row(row)
        self._scroll_row_into_view(row)

    def _scroll_row_into_view(self, row: Gtk.ListBoxRow) -> None:
        try:
            ok, rect = row.compute_bounds(self._menu)
        except Exception:  # noqa: BLE001 -- best-effort only, never fatal
            return
        if not ok:
            return
        adj = self._scroller.get_vadjustment()
        top = rect.origin.y
        bottom = top + rect.size.height
        if top < adj.get_value():
            adj.set_value(top)
        elif bottom > adj.get_value() + adj.get_page_size():
            adj.set_value(bottom - adj.get_page_size())

    def _move_selection(self, delta: int) -> None:
        if not self._nav_rows:
            return
        if self._selected_index < 0:
            new_index = 0
        else:
            new_index = max(0, min(len(self._nav_rows) - 1, self._selected_index + delta))
        self._select_index(new_index)

    def _activate_selected(self) -> None:
        if 0 <= self._selected_index < len(self._nav_rows):
            self._on_account_activated(self._nav_rows[self._selected_index].summary)

    def _on_search_activate(self, _entry: Gtk.SearchEntry) -> None:
        self._activate_selected()

    def _on_row_activated(self, _listbox, row: Gtk.ListBoxRow) -> None:
        if isinstance(row, AccountRow):
            self._on_account_activated(row.summary)

    def _on_key_pressed(self, _controller, keyval, _keycode, _state):
        from gi.repository import Gdk

        if keyval == Gdk.KEY_Escape:
            self.close()
            return True
        if keyval in (Gdk.KEY_Down, Gdk.KEY_KP_Down):
            self._move_selection(1)
            return True
        if keyval in (Gdk.KEY_Up, Gdk.KEY_KP_Up):
            self._move_selection(-1)
            return True
        return False

    # -- account activation / Safety Guard -------------------------------

    def _on_account_activated(self, summary: AccountSummary) -> None:
        vault = self.app.session.vault()
        secrets = vault.get_account_secrets(summary.entry_uuid)
        strategy = AuthStrategy.from_json(secrets.auth_strategy_json)
        context = self.app.detected_context
        guard_mode = SafetyGuardMode(self.app.settings.safety_guard_mode)

        # Decide *before* typing anything -- separate from the async
        # login run specifically so a CONFIRM_REQUIRED decision never
        # has to hide this window first (see _hide_and_execute's
        # docstring for why hiding matters once we do proceed to type).
        confidence = confidence_for_account(context, secrets)
        decision = evaluate_safety_guard(guard_mode, confidence)
        if decision == GuardDecision.CONFIRM_REQUIRED:
            secrets.wipe()
            self._show_confirmation(summary, context)
            return

        self._hide_and_execute(secrets, strategy, context, guard_mode, confirmed=True)

    def _show_confirmation(self, summary: AccountSummary, context) -> None:
        window_desc = context.app_id or context.window_title or "the current window"
        self._confirm_bar.set_title(f"Sign in to {summary.display_name} in {window_desc}?")
        self._confirm_bar.set_button_label("Proceed")
        self._confirm_bar.set_revealed(True)

        def on_confirm(_b):
            self._confirm_bar.set_revealed(False)
            self._run_confirmed(summary)

        # Adw.Banner only supports one button; disconnect any previous handler.
        if hasattr(self, "_confirm_handler_id") and self._confirm_handler_id:
            self._confirm_bar.disconnect(self._confirm_handler_id)
        self._confirm_handler_id = self._confirm_bar.connect("button-clicked", on_confirm)

    def _run_confirmed(self, summary: AccountSummary) -> None:
        vault = self.app.session.vault()
        secrets = vault.get_account_secrets(summary.entry_uuid)
        strategy = AuthStrategy.from_json(secrets.auth_strategy_json)
        context = self.app.detected_context
        guard_mode = SafetyGuardMode(self.app.settings.safety_guard_mode)
        self._hide_and_execute(secrets, strategy, context, guard_mode, confirmed=True)

    def _hide_and_execute(self, secrets, strategy, context, guard_mode, confirmed: bool) -> None:
        """Hide this window and give the compositor a moment to restore
        focus to whatever was focused before the picker took it, THEN
        type -- discovered live (not by unit tests, which never exercise
        real window focus at all) that without this step, autotype would
        type into the picker's own window, since that's what actually
        has keyboard focus at the moment the user clicks an account tile.
        ``confirmed`` is always True here: the Safety Guard decision was
        already made in ``_on_account_activated``/before showing the
        confirmation banner -- this method never re-decides it.

        The 250ms delay below is the only thing that still runs as a
        plain ``GLib.timeout_add`` callback -- it does no work of its
        own beyond starting the background login run, so it never blocks
        anything. Backend selection (an AT-SPI probe plus a possible
        ``pgrep`` for ydotoold) and the strategy run itself (subprocess
        calls, WAIT-step sleeps) both happen on a background thread via
        ``run_login_async`` -- never here, never on this thread."""
        allow_clipboard_fallback = self.app.settings.clipboard_fallback_enabled
        self._toast_overlay.add_toast(Adw.Toast(title="Signing in…", timeout=2))
        self.set_visible(False)

        def start_worker() -> bool:
            run_login_async(
                lambda: select_backend(allow_clipboard_fallback=allow_clipboard_fallback),
                secrets,
                strategy,
                context,
                guard_mode,
                confirmed,
                on_done=self._on_login_finished,
            )
            return False

        GLib.timeout_add(250, start_worker)

    def _on_login_finished(self, result) -> None:
        self.set_visible(True)
        self.present()
        self._report_login_result(result)

    def _report_login_result(self, result) -> None:
        messages = {
            LoginOutcome.SUCCESS: "Signed in",
            LoginOutcome.FAILED: "Unable to complete sign-in automatically.",
            LoginOutcome.NO_BACKEND: "No input method available. Enable ydotoold or AT-SPI.",
            LoginOutcome.NEEDS_CONFIRMATION: "Confirmation required.",
        }
        _log.info("login attempt finished", extra=safe_extra(event="login_result", outcome=result.outcome.value))
        self._toast_overlay.add_toast(Adw.Toast(title=messages.get(result.outcome, "Done.")))

    # -- toolbar actions --------------------------------------------------

    def _on_open_generator(self, _btn) -> None:
        GeneratorDialog(self).present(self)

    def _on_open_settings(self, _btn) -> None:
        SettingsDialog(self.app).present(self)

    def _on_add_account(self, _btn) -> None:
        dialog = EntryEditorDialog(self.app, on_saved=self.refresh_accounts)
        dialog.present(self)

    def destroy_sensitive_state(self) -> None:
        self._all_accounts = []
        self._app_ids_by_uuid = {}
        self._fill_menu([], [])
