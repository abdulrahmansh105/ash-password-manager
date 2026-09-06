"""Small, reusable widget builders shared across the new setup/login
surfaces (spec sections 2-11). Kept separate from the one-off dialogs
in ``entry_editor.py``/``account_detail.py``/``generator_view.py`` --
those are complete, self-contained dialogs; these are fragments
composed into several different windows/pages.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk


def accelerator_display_label(accelerator: str) -> str:
    """"<Control><Alt>p" -> "Ctrl+Alt+P". Never pass a raw accelerator
    string as an Adw row *title* -- those are parsed as Pango markup,
    and "<Ctrl>" is invalid markup (verified live during development;
    it logs an Adwaita-CRITICAL and fails to render). Use this display
    form, or a plain (non-title) Gtk.Label, instead."""
    ok, keyval, mods = Gtk.accelerator_parse(accelerator)
    return Gtk.accelerator_get_label(keyval, mods) if ok else accelerator


def build_brand_header(subtitle: str) -> Gtk.Widget:
    """"ASH Password Manager" over a secondary state label (spec
    section 22: "Primary title" / "Secondary state"), used at the top
    of every setup/login page."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, halign=Gtk.Align.CENTER)
    title = Gtk.Label(label="ASH Password Manager", xalign=0.5)
    title.add_css_class("title-2")
    title.add_css_class("ash-brand-title")
    box.append(title)
    sub = Gtk.Label(label=subtitle, xalign=0.5)
    sub.add_css_class("ash-subtitle")
    box.append(sub)
    return box


def build_local_key_offer_content(on_skip, on_generate) -> Gtk.Widget:
    """Spec section 4's exact "Create Local Key" choice: Skip on the
    LEFT, Generate Key (the primary/suggested action) on the right.
    Shared between the first-run wizard's LOCAL_KEY_OPTIONAL step and
    the login window's "register this new device?" offer (spec
    section 5) -- both are the same product decision."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, halign=Gtk.Align.CENTER, margin_top=8)
    skip_btn = Gtk.Button(label="Skip")
    skip_btn.connect("clicked", on_skip)
    generate_btn = Gtk.Button(label="Generate Key")
    generate_btn.add_css_class("suggested-action")
    generate_btn.connect("clicked", on_generate)
    row.append(skip_btn)
    row.append(generate_btn)
    return row


def build_step_dots(total: int, current_index: int) -> Gtk.Widget:
    """A minimal progress indicator for the setup wizard -- small dots,
    the current step highlighted, matching the "clean, minimal" brand
    direction (spec section 22) rather than a heavier progress bar."""
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6, halign=Gtk.Align.CENTER)
    for i in range(total):
        dot = Gtk.Box(width_request=8, height_request=8)
        dot.add_css_class("ash-step-dot")
        if i == current_index:
            dot.add_css_class("active")
        box.append(dot)
    return box


def build_error_banner() -> Gtk.Label:
    label = Gtk.Label(xalign=0, wrap=True)
    label.add_css_class("pm-error-label")
    label.set_visible(False)
    return label
