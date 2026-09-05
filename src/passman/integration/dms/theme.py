"""DankMaterialShell theme awareness.

Deliberately thin: DMS writes a Matugen-generated GTK4 theme to
``~/.config/gtk-4.0/gtk.css`` using standard named GTK colors
(``@accent_bg_color``, ``@window_bg_color``, ...) -- exactly the approach
password-template-generator's GUI already relied on. As long as this
app's own CSS (``ui/style.css``) only overrides shape/spacing and never
hardcodes a color, GTK/Libadwaita picks up DMS's live theme automatically
with zero custom DMS-reading code, and updates live when DMS's theme
changes (GTK re-reads ``gtk.css`` on change).

This module exists only for the one thing CSS can't express: which
Adwaita color-scheme (light/dark) is currently active, for anything that
needs to branch in Python (e.g. choosing an icon variant).
"""

from __future__ import annotations


def is_dark_preferred() -> bool:
    try:
        import gi

        gi.require_version("Adw", "1")
        from gi.repository import Adw

        manager = Adw.StyleManager.get_default()
        return bool(manager.get_dark())
    except Exception:  # noqa: BLE001
        return False
