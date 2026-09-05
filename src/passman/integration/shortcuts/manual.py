"""Manual fallback (spec section 9): always "available" -- it never
touches the system, it only tells the user what to configure
themselves and where. This is the honest fallback for desktop
environments this project has no verified automatic mechanism for
(KDE Plasma, Sway, and anything else not covered by the portal,
Hyprland, or GNOME backends) -- shown instead of a backend this
project cannot confirm actually creates a working shortcut, per the
project's "never claim a feature works unless it does" standard.
"""

from __future__ import annotations

from .backend import BindOutcome, BindResult, ShortcutBackend


class ManualShortcutBackend(ShortcutBackend):
    name = "manual"

    def is_available(self) -> bool:
        return True

    def bind(self, accelerator: str, exec_cmd: str, description: str) -> BindOutcome:
        return BindOutcome(
            BindResult.UNAVAILABLE,
            f"Add this shortcut in your desktop's keyboard settings: {accelerator} -> {exec_cmd}",
        )
