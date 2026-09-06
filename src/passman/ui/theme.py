"""ASH Password Manager's branded visual identity (spec section 22):
white, blue, clean, modern, minimal, professional.

Implemented the same way DankMaterialShell's own live theme already is
(see ``style.css``'s docstring): GTK4 named-color overrides, loaded as
a second ``Gtk.CssProvider`` at application priority -- which is
*higher* than the DMS-injected ``~/.config/gtk-4.0/gtk.css`` (loaded
at GTK's own theme/settings priority), so this coexists with it
cleanly and, when selected, simply wins. No custom widget painting, no
per-widget color-setting code anywhere else in the UI -- every stock
Libadwaita widget (buttons, switches, header bars, `.card`s) already
consumes these same named colors, so they all pick up the brand look
automatically.

This intentionally supersedes ``style.css``'s original "never set a
color" rule for the one case the product spec explicitly asks for a
specific brand identity. "Follow system / DMS theme" remains one
Settings toggle away (``Settings.theme = "dms"``) and keeps the
original zero-hardcoded-color behavior exactly as it was.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, Gtk

# Blue-600/Slate palette: accessible contrast on white, calm enough
# for a security-sensitive tool (spec section 22: "avoid clutter").
ACCENT = "#2563EB"
ACCENT_HOVER = "#1D4ED8"
ACCENT_FG = "#FFFFFF"
INK = "#0F172A"
INK_MUTED = "#475569"
SURFACE = "#FFFFFF"
SURFACE_SUNKEN = "#F8FAFC"
BORDER = "#E2E8F0"

ASH_THEME_CSS = f"""
@define-color accent_color {ACCENT};
@define-color accent_bg_color {ACCENT};
@define-color accent_fg_color {ACCENT_FG};

@define-color window_bg_color {SURFACE};
@define-color window_fg_color {INK};
@define-color view_bg_color {SURFACE};
@define-color view_fg_color {INK};
@define-color headerbar_bg_color {SURFACE};
@define-color headerbar_fg_color {INK};
@define-color headerbar_border_color {BORDER};
@define-color headerbar_backdrop_color {SURFACE};
@define-color headerbar_shade_color alpha(black, 0.06);
@define-color card_bg_color {SURFACE};
@define-color card_fg_color {INK};
@define-color card_shade_color alpha(black, 0.06);
@define-color dialog_bg_color {SURFACE};
@define-color dialog_fg_color {INK};
@define-color popover_bg_color {SURFACE};
@define-color popover_fg_color {INK};
@define-color shade_color alpha(black, 0.06);
@define-color scrollbar_outline_color {BORDER};

/* Structural touches only (shape/spacing/emphasis), matching the
   existing style.css convention -- these classes are opt-in on
   specific widgets, never a blanket selector fighting the theme. */
.ash-brand-title {{ font-weight: 800; letter-spacing: -0.01em; }}
.ash-subtitle {{ color: {INK_MUTED}; font-size: 0.95em; }}
.ash-hero-icon {{ color: {ACCENT}; }}
.ash-card {{ background-color: {SURFACE_SUNKEN}; border: 1px solid {BORDER}; border-radius: 12px; }}
.ash-step-dot {{ min-width: 8px; min-height: 8px; border-radius: 999px; background-color: {BORDER}; }}
.ash-step-dot.active {{ background-color: {ACCENT}; }}
button.suggested-action {{ background-color: {ACCENT}; }}
button.suggested-action:hover {{ background-color: {ACCENT_HOVER}; }}
"""


def apply_ash_theme(display: Gdk.Display | None = None) -> Gtk.CssProvider:
    """Load the ASH brand stylesheet at application priority. Returns
    the provider so a caller can remove it later (e.g. the user
    switches to "Follow system" in Settings without restarting)."""
    provider = Gtk.CssProvider()
    provider.load_from_string(ASH_THEME_CSS)
    target_display = display or Gdk.Display.get_default()
    if target_display is not None:
        Gtk.StyleContext.add_provider_for_display(target_display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    return provider


def remove_ash_theme(provider: Gtk.CssProvider, display: Gdk.Display | None = None) -> None:
    target_display = display or Gdk.Display.get_default()
    if target_display is not None:
        Gtk.StyleContext.remove_provider_for_display(target_display, provider)
