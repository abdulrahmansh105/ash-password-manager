"""Global-hotkey registration (spec section 9), across desktop
environments without assuming Hyprland (spec section 20).

Preference order: the XDG GlobalShortcuts portal (desktop-agnostic,
works wherever implemented) -> Hyprland's native mechanism (this
project's primary target) -> GNOME's gsettings custom keybindings ->
Manual (always available, never silently fails -- it just tells the
user what to do). ``select_and_bind`` tries each in turn and stops at
the first one that actually succeeds, matching ``input/__init__.py``'s
existing ``select_backend`` preference-order idiom.
"""

from __future__ import annotations

from .backend import BindOutcome, BindResult, ShortcutBackend
from .gnome import GnomeShortcutBackend
from .hyprland import HyprlandShortcutBackend
from .manual import ManualShortcutBackend
from .portal import PortalShortcutBackend

__all__ = [
    "BindOutcome",
    "BindResult",
    "ShortcutBackend",
    "GnomeShortcutBackend",
    "HyprlandShortcutBackend",
    "ManualShortcutBackend",
    "PortalShortcutBackend",
    "available_backends",
    "select_and_bind",
]


def available_backends() -> list[ShortcutBackend]:
    candidates: list[ShortcutBackend] = [
        PortalShortcutBackend(),
        HyprlandShortcutBackend(),
        GnomeShortcutBackend(),
    ]
    available = [b for b in candidates if _safe_is_available(b)]
    available.append(ManualShortcutBackend())  # always last, always available
    return available


def _safe_is_available(backend: ShortcutBackend) -> bool:
    try:
        return backend.is_available()
    except Exception:  # noqa: BLE001 - a broken backend probe must never crash setup
        return False


def select_and_bind(accelerator: str, exec_cmd: str, description: str) -> tuple[ShortcutBackend, BindOutcome]:
    """Tries each available backend in preference order and returns
    the first one that actually succeeds (not just "is available" --
    the portal in particular can still fail/time out if the user
    cancels its confirmation UI). Always returns *something* --
    Manual's outcome if nothing else worked -- so the caller never has
    to handle "no backend at all"."""
    last: tuple[ShortcutBackend, BindOutcome] | None = None
    for backend in available_backends():
        try:
            outcome = backend.bind(accelerator, exec_cmd, description)
        except Exception as exc:  # noqa: BLE001 - one backend's bug must not block the others
            outcome = BindOutcome(BindResult.FAILED, f"{type(exc).__name__}: {exc}")
        last = (backend, outcome)
        if outcome.result == BindResult.OK:
            return last
    return last  # last is always set: available_backends() always includes Manual
