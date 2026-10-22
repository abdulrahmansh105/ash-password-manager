"""Password generator, promoted to a first-class part of the app (spec
section 17) rather than a separate tool. Preserves the deterministic
template engine exactly (ported unchanged in ``core.generator``) and
adds a CSPRNG random mode alongside it.

Clipboard note: the explicit "Copy" button here is a distinct, ordinary
password-manager action (the user deliberately copying a password they
are about to paste somewhere, e.g. a signup form) from the *autotype
fallback* clipboard path gated by "Allow clipboard fallback" in Settings
(spec section 16, about the sign-in flow specifically). This button
always works, using the same safe generation-tracked auto-clear as
password-template-generator's clipboard manager, and never logs the
value. Generated text otherwise only exists in the entry widget's
buffer and is cleared when the dialog closes (spec section 19).
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..core.generator import (
    PolicyError,
    RandomPasswordPolicy,
    TemplateError,
    generate,
    generate_random_password,
)

from .widgets import page_intro, style_window


class GeneratorDialog(Adw.Dialog):
    def __init__(self, parent_window) -> None:
        super().__init__(title="Password Generator", content_width=540, content_height=660)
        style_window(self, parent_window.app.settings)
        self._sensitive_entries = []
        self.connect("closed", self._on_closed)
        self._parent_window = parent_window
        self._clipboard = parent_window.app.session.clipboard

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        self._toast = Adw.ToastOverlay()
        self._toast.set_child(toolbar_view)
        self.set_child(self._toast)

        self._stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher(stack=self._stack, policy=Adw.ViewSwitcherPolicy.WIDE)
        toolbar_view.add_top_bar(switcher)
        toolbar_view.set_content(self._stack)

        self._stack.add_titled_with_icon(self._build_random_page(), "random", "Random", "view-refresh-symbolic")
        self._stack.add_titled_with_icon(self._build_template_page(), "template", "Template", "view-list-symbolic")
        self._stack.set_visible_child_name("random")

    def _with_result_bar(self, page, generate_btn, result_box, error_label):
        toolbar = Adw.ToolbarView()
        toolbar.set_content(page)
        bar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_start=24, margin_end=24, margin_top=8, margin_bottom=16)
        bar.append(result_box)
        bar.append(error_label)
        bar.append(generate_btn)
        toolbar.add_bottom_bar(bar)
        return toolbar

    def _build_result_row(self) -> tuple[Gtk.Box, Gtk.Entry, Gtk.Label]:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        entry = Gtk.Entry(editable=False, hexpand=True)
        entry.add_css_class("pm-password-row")
        entry.set_placeholder_text("Your generated password")
        self._sensitive_entries.append(entry)
        copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        copy_btn.set_tooltip_text("Copy generated password")
        copy_btn.set_sensitive(False)
        entry.connect("changed", lambda e: copy_btn.set_sensitive(bool(e.get_text())))
        error_label = Gtk.Label(xalign=0, wrap=True)
        error_label.add_css_class("pm-error-label")
        error_label.set_visible(False)

        def on_copy(_b):
            text = entry.get_text()
            if not text:
                return
            status = self._clipboard.copy(text, self._parent_window.app.settings.clipboard_timeout_seconds())
            error_label.set_visible(not status.copied)
            if not status.copied:
                error_label.set_text(status.error or "Copy failed.")
            else:
                self._toast.add_toast(Adw.Toast(title="Password copied"))

        copy_btn.connect("clicked", on_copy)
        box.append(entry)
        box.append(copy_btn)
        return box, entry, error_label

    def _build_template_page(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()
        page.add(page_intro("From your template", "The same template and inputs produce the same password.", "view-list-symbolic", compact=True))
        group = Adw.PreferencesGroup(title="Template inputs")

        template_row = Adw.EntryRow(title="Template")
        username_row = Adw.EntryRow(title="Username")
        service_row = Adw.EntryRow(title="Service name")
        self._sensitive_entries.extend((template_row, username_row, service_row))
        group.add(template_row)
        group.add(username_row)
        group.add(service_row)

        result_box, result_entry, error_label = self._build_result_row()

        generate_btn = Gtk.Button(label="Generate password")
        generate_btn.add_css_class("suggested-action")
        generate_btn.add_css_class("pm-generate-button")

        def on_generate(_b):
            try:
                value = generate(
                    template_row.get_text(),
                    username=username_row.get_text(),
                    service_name=service_row.get_text(),
                )
                result_entry.set_text(value)
                error_label.set_visible(False)
            except TemplateError as exc:
                error_label.set_text(str(exc))
                error_label.set_visible(True)
                result_entry.set_text("")

        generate_btn.connect("clicked", on_generate)

        page.add(group)
        return self._with_result_bar(page, generate_btn, result_box, error_label)

    def _build_random_page(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()
        page.add(page_intro("A stronger password", "Create a unique password with the characters you choose.", compact=True))
        group = Adw.PreferencesGroup(title="Password options")

        length_row = Adw.SpinRow.new_with_range(8, 128, 1)
        length_row.set_title("Length")
        length_row.set_value(24)

        lower_row = Adw.SwitchRow(title="Lowercase", active=True)
        upper_row = Adw.SwitchRow(title="Uppercase", active=True)
        digits_row = Adw.SwitchRow(title="Digits", active=True)
        symbols_row = Adw.SwitchRow(title="Symbols", active=True)
        ambiguous_row = Adw.SwitchRow(title="Exclude ambiguous characters (Il1O0)", active=False)

        for row in (length_row, lower_row, upper_row, digits_row, symbols_row, ambiguous_row):
            group.add(row)

        result_box, result_entry, error_label = self._build_result_row()

        generate_btn = Gtk.Button(label="Generate password")
        generate_btn.add_css_class("suggested-action")
        generate_btn.add_css_class("pm-generate-button")

        def on_generate(_b):
            policy = RandomPasswordPolicy(
                length=int(length_row.get_value()),
                use_lower=lower_row.get_active(),
                use_upper=upper_row.get_active(),
                use_digits=digits_row.get_active(),
                use_symbols=symbols_row.get_active(),
                exclude_ambiguous=ambiguous_row.get_active(),
            )
            try:
                result_entry.set_text(generate_random_password(policy))
                error_label.set_visible(False)
            except PolicyError as exc:
                error_label.set_text(str(exc))
                error_label.set_visible(True)
                result_entry.set_text("")

        generate_btn.connect("clicked", on_generate)

        page.add(group)
        return self._with_result_bar(page, generate_btn, result_box, error_label)

    def _on_closed(self, _dialog) -> None:
        for entry in self._sensitive_entries:
            entry.set_text("")
