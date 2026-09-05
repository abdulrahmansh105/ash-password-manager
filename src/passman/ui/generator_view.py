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
from gi.repository import Adw, Gtk  # noqa: E402

from ..core.generator import (
    PolicyError,
    RandomPasswordPolicy,
    TemplateError,
    generate,
    generate_random_password,
)
from ..core.security.clipboard import ClipboardManager


class GeneratorDialog(Adw.Dialog):
    def __init__(self, parent_window) -> None:
        super().__init__(title="Password Generator", content_width=420, content_height=420)
        self._parent_window = parent_window
        self._clipboard = ClipboardManager()

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        self.set_child(toolbar_view)

        self._stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher(stack=self._stack, policy=Adw.ViewSwitcherPolicy.WIDE)
        toolbar_view.add_top_bar(switcher)
        toolbar_view.set_content(self._stack)

        self._stack.add_titled(self._build_template_page(), "template", "Template")
        self._stack.add_titled(self._build_random_page(), "random", "Random")

    def _build_result_row(self) -> tuple[Gtk.Box, Gtk.Entry, Gtk.Label]:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        entry = Gtk.Entry(editable=False, hexpand=True)
        entry.add_css_class("pm-password-row")
        copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        error_label = Gtk.Label(xalign=0)
        error_label.add_css_class("pm-error-label")
        error_label.set_visible(False)

        def on_copy(_b):
            text = entry.get_text()
            if not text:
                return
            status = self._clipboard.copy(text, 30)
            error_label.set_visible(not status.copied)
            if not status.copied:
                error_label.set_text(status.error or "Copy failed.")

        copy_btn.connect("clicked", on_copy)
        box.append(entry)
        box.append(copy_btn)
        return box, entry, error_label

    def _build_template_page(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(title="Deterministic template")

        template_row = Adw.EntryRow(title="Template")
        username_row = Adw.EntryRow(title="Username")
        service_row = Adw.EntryRow(title="Service name")
        group.add(template_row)
        group.add(username_row)
        group.add(service_row)

        result_box, result_entry, error_label = self._build_result_row()

        generate_btn = Gtk.Button(label="Generate")
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

        group.add(generate_btn)
        group.add(result_box)
        group.add(error_label)
        page.add(group)
        return page

    def _build_random_page(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(title="Random (CSPRNG)")

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

        generate_btn = Gtk.Button(label="Generate")
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

        group.add(generate_btn)
        group.add(result_box)
        group.add(error_label)
        page.add(group)
        return page
