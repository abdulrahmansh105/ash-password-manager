"""Hyprland backend (spec section 9), built entirely on the existing,
unmodified ``integration.hyprland.keybind`` module (``hyprctl keyword
bind``, already used for the original SUPER+CTRL+A shortcut).

Persistence works by having the background agent re-issue the runtime
bind at every login (``reapply_on_startup``) rather than by writing to
the user's own Hyprland config file. This is a deliberate choice, not
an oversight: this project's own development machine configures
Hyprland via a Lua DSL (``hyprland.lua`` -> ``hl.config``/``hl.on``),
not the classic ``bind = ...`` text format
``integration.hyprland.keybind.write_persistent_include`` writes --
so a config-file write cannot be assumed to work, or even be sourced,
across the diversity of ways people configure Hyprland. Re-applying
the runtime bind at agent startup works identically regardless of
config format and needs no assumption about it at all. That existing
function is still available (and still used by the original
``password-manager setup`` CLI flow) for users who want a persistent
text-format include and know their config can source one.
"""

from __future__ import annotations

from ..hyprland import keybind
from .backend import BindOutcome, BindResult, ShortcutBackend

_KEY_ALIASES = {"space": "SPACE", "tab": "Tab", "return": "Return", "enter": "Return", "escape": "Escape"}
_MOD_ALIASES = {"control": "CTRL", "ctrl": "CTRL", "alt": "ALT", "shift": "SHIFT", "super": "SUPER", "primary": "CTRL"}


def _accelerator_to_hyprland(accelerator: str) -> tuple[str, str] | None:
    """"<Ctrl><Alt>p" -> ("CTRL ALT", "P") -- the space-separated mod
    string ``register_runtime_bind`` itself expects (it does the
    underscore-joining for hyprctl's own syntax internally). Returns
    None for anything this simple parser doesn't recognize; callers
    fall back to another backend or Manual rather than guess."""
    mods = []
    rest = accelerator
    while rest.startswith("<"):
        end = rest.find(">")
        if end == -1:
            return None
        token = rest[1:end].lower()
        if token not in _MOD_ALIASES:
            return None
        mods.append(_MOD_ALIASES[token])
        rest = rest[end + 1 :]
    if not rest:
        return None
    key = _KEY_ALIASES.get(rest.lower(), rest.upper() if len(rest) == 1 else rest)
    return " ".join(mods), key


class HyprlandShortcutBackend(ShortcutBackend):
    name = "hyprland"

    def is_available(self) -> bool:
        return keybind.is_available()

    def bind(self, accelerator: str, exec_cmd: str, description: str) -> BindOutcome:
        parsed = _accelerator_to_hyprland(accelerator)
        if parsed is None:
            return BindOutcome(BindResult.FAILED, "Could not translate this accelerator for Hyprland.")
        mods, key = parsed
        if not keybind.register_runtime_bind(exec_cmd, mods=mods, key=key):
            return BindOutcome(BindResult.FAILED, "hyprctl keyword bind failed.")
        return BindOutcome(BindResult.OK)

    def reapply_on_startup(self, accelerator: str, exec_cmd: str, description: str) -> None:
        self.bind(accelerator, exec_cmd, description)
