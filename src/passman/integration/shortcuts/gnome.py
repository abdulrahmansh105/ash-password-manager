"""GNOME backend (spec section 9): a custom keybinding via
``gsettings``, the same mechanism GNOME Settings' own "Keyboard
Shortcuts" panel uses (``org.gnome.settings-daemon.plugins.media-
keys.custom-keybinding``) -- stable, simple, and unchanged for over a
decade. Implemented against the documented mechanism, but -- like this
project's existing AT-SPI autotype backend (see
docs/INPUT_BACKENDS.md) -- not exercised against a live GNOME Shell
session in this project's own development environment (Hyprland is
the active compositor here). It only ever activates when the schema
is actually queryable at runtime, never assumed from the desktop name
alone.
"""

from __future__ import annotations

import ast
import subprocess

from .backend import BindOutcome, BindResult, ShortcutBackend

_BASE_SCHEMA = "org.gnome.settings-daemon.plugins.media-keys"
_CUSTOM_PATH_PREFIX = "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/"
_CUSTOM_SCHEMA = "org.gnome.settings-daemon.plugins.media-keys.custom-keybinding"
_OUR_SLOT_NAME = "ash-password-manager-open"
_SLOT_PATH = f"{_CUSTOM_PATH_PREFIX}{_OUR_SLOT_NAME}/"


def _run(*args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["gsettings", *args], capture_output=True, timeout=5, check=False)
    except (subprocess.SubprocessError, OSError):
        return None


class GnomeShortcutBackend(ShortcutBackend):
    name = "gnome"

    def is_available(self) -> bool:
        result = _run("get", _BASE_SCHEMA, "custom-keybindings")
        return result is not None and result.returncode == 0

    def _existing_paths(self) -> list[str]:
        result = _run("get", _BASE_SCHEMA, "custom-keybindings")
        if result is None or result.returncode != 0:
            return []
        raw = result.stdout.decode("utf-8", "replace").strip()
        try:
            parsed = ast.literal_eval(raw) if raw else []
            return list(parsed) if isinstance(parsed, (list, tuple)) else []
        except (ValueError, SyntaxError):
            return []

    def bind(self, accelerator: str, exec_cmd: str, description: str) -> BindOutcome:
        if not self.is_available():
            return BindOutcome(BindResult.UNAVAILABLE)

        paths = self._existing_paths()
        if _SLOT_PATH not in paths:
            paths.append(_SLOT_PATH)
            if (result := _run("set", _BASE_SCHEMA, "custom-keybindings", repr(paths))) is None or result.returncode != 0:
                return BindOutcome(BindResult.FAILED, "Could not register the custom keybinding slot.")

        schema_with_path = f"{_CUSTOM_SCHEMA}:{_SLOT_PATH}"
        for key, value in (("name", description), ("command", exec_cmd), ("binding", accelerator)):
            result = _run("set", schema_with_path, key, value)
            if result is None or result.returncode != 0:
                return BindOutcome(BindResult.FAILED, f"gsettings set failed for {key!r}.")
        return BindOutcome(BindResult.OK)
