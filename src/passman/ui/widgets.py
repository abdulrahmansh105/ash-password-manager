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
from gi.repository import Adw, Gdk, Gtk
from pathlib import Path

_STYLE_PROVIDER = None


def style_window(window, settings=None) -> None:
    """Install shared styling for every entry point, including setup/login."""
    global _STYLE_PROVIDER
    if _STYLE_PROVIDER is None and Gdk.Display.get_default() is not None:
        _STYLE_PROVIDER = Gtk.CssProvider()
        _STYLE_PROVIDER.load_from_path(str(Path(__file__).with_name("style.css")))
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), _STYLE_PROVIDER, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    gtk_settings = Gtk.Settings.get_default()
    if gtk_settings is not None:
        gtk_settings.set_property("gtk-enable-animations", False)
    window.add_css_class("pm-window")
    if settings is not None and settings.ui_density == "compact":
        window.add_css_class("pm-compact")


def form_page(body: Gtk.Widget, maximum_size: int = 460) -> Gtk.Widget:
    """Scrollable, width-constrained content for small and wide windows."""
    clamp = Adw.Clamp(maximum_size=maximum_size, tightening_threshold=320)
    clamp.set_child(body)
    scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
    scroller.set_child(clamp)
    return scroller


def page_intro(title: str, description: str, icon: str = "dialog-password-symbolic", *, compact: bool = False) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_bottom=12)
    image = Gtk.Image.new_from_icon_name(icon)
    image.set_pixel_size(28)
    image.set_halign(Gtk.Align.START)
    image.add_css_class("ash-hero-icon")
    if not compact:
        box.append(image)
    heading = Gtk.Label(label=title, xalign=0, wrap=True)
    heading.add_css_class("pm-page-heading")
    box.append(heading)
    detail = Gtk.Label(label=description, xalign=0, wrap=True)
    detail.add_css_class("pm-subtitle")
    box.append(detail)
    group = Adw.PreferencesGroup()
    group.add(box)
    return group


def icon_button(icon: str, label: str, callback) -> Gtk.Button:
    button = Gtk.Button.new_from_icon_name(icon)
    button.set_tooltip_text(label)
    button.update_property([Gtk.AccessibleProperty.LABEL], [label])
    button.connect("clicked", callback)
    return button



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
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin_bottom=8)
    icon = Gtk.Image.new_from_icon_name("channel-secure-symbolic")
    icon.set_pixel_size(32)
    icon.set_halign(Gtk.Align.CENTER)
    icon.add_css_class("ash-hero-icon")
    box.append(icon)
    title = Gtk.Label(label="ASH Password Manager", wrap=True)
    title.add_css_class("ash-brand-title")
    title.add_css_class("title-2")
    box.append(title)
    sub = Gtk.Label(label=subtitle, wrap=True)
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
    skip_btn = Gtk.Button(label="Skip for now")
    skip_btn.connect("clicked", on_skip)
    generate_btn = Gtk.Button(label="Create device key")
    generate_btn.add_css_class("suggested-action")
    generate_btn.add_css_class("pm-primary")
    generate_btn.connect("clicked", on_generate)
    row.append(skip_btn)
    row.append(generate_btn)
    return row


def build_step_dots(total: int, current_index: int) -> Gtk.Widget:
    """A minimal progress indicator for the setup wizard -- small dots,
    the current step highlighted, matching the "clean, minimal" brand
    direction (spec section 22) rather than a heavier progress bar."""
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6, halign=Gtk.Align.CENTER)
    box.add_css_class("pm-step-track")
    box.update_property([Gtk.AccessibleProperty.LABEL], [f"Step {current_index + 1} of {total}"])
    for i in range(total):
        dot = Gtk.Box(height_request=4)
        dot.add_css_class("ash-step-dot")
        if i == current_index:
            dot.add_css_class("active")
        elif i < current_index:
            dot.add_css_class("complete")
        box.append(dot)
    return box


def build_error_banner() -> Gtk.Label:
    label = Gtk.Label(xalign=0, wrap=True)
    label.add_css_class("pm-error-label")
    label.set_visible(False)
    return label
