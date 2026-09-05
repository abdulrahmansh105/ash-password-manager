"""Hyprland global-shortcut integration.

Deliberately does NOT edit the user's ``hyprland.conf`` by hand -- that's
fragile (duplicate binds on re-run, hard to find/remove later, breaks if
the file uses non-standard structure). Instead this uses Hyprland's own
IPC to register a bind at runtime.

That IPC mechanism itself has changed underneath this project: on
Hyprland >= ~0.5x (confirmed on 0.56.2, this project's own development
machine), the classic ``hyprctl keyword bind "MODS,KEY,exec,CMD"``
call exits 0 but registers nothing at all, printing "keyword can't
work with non-legacy parsers. Use eval." to stdout instead -- a
version-drift regression discovered live on this exact machine, not a
hypothetical. The correct current mechanism (also confirmed live) is
``hyprctl eval "hl.bind('<MOD+MOD+KEY>', hl.dsp.exec_cmd('<cmd>'))"``,
Hyprland's Lua scripting API (``hl.bind``/``hl.dsp.exec_cmd``, queried
directly via ``hyprctl repl`` on this machine to discover the exact
signature and argument-error messages). ``register_runtime_bind``
below never trusts that eval's own exit code either -- it separately
re-queries ``hyprctl binds -j`` and only reports success if a bind
with the exact modmask/key it just asked for is actually present,
since a lying exit code is exactly what broke the old mechanism.

Because a runtime bind does not survive a Hyprland restart,
``password-manager setup`` also writes ONE small, clearly-delimited
include file (not touching the user's own config) and prints the
single line needed to source it -- the user adds that one line
themselves rather than this tool silently rewriting their config, per
this project's "don't silently modify shared config" policy. That
file uses Hyprland's plain config-file ``bind = ...`` syntax, parsed
by Hyprland at config load time -- a completely different code path
from the runtime IPC above, unaffected by the eval/keyword change.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

DEFAULT_MODS = "SUPER CTRL"
DEFAULT_KEY = "A"
INCLUDE_FILENAME = "password-manager.conf"

# Standard wlroots keyboard-modifier bitmask (confirmed empirically via
# `hyprctl binds -j` after a known SUPER+ALT+SHIFT bind: reported
# modmask 73 == 64+8+1). Only the four modifiers this project's own
# accelerator parser (``integration.shortcuts.hyprland._MOD_ALIASES``)
# ever produces are needed here.
_MODMASK_BITS = {"SHIFT": 1, "CTRL": 4, "ALT": 8, "SUPER": 64}


def _modmask_for(mods: str) -> int:
    mask = 0
    for name in mods.split():
        mask |= _MODMASK_BITS.get(name.upper(), 0)
    return mask


def _lua_string_literal(value: str) -> str:
    """Safely embed an arbitrary string as a single-quoted Lua string
    literal -- the exec command is a fixed constant today, but this
    must not silently break (or worse, allow Lua injection) if that
    ever changes."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


# GTK4/Wayland apps report their D-Bus application ID as the window
# class Hyprland sees, matching Adw.Application's `application_id` (see
# ui/app.py's APP_ID / ui/locked_window.py's APP_ID) -- these window
# rules are what make the account picker and the locked popup read as
# small floating windows instead of getting tiled like a normal window,
# satisfying the "floating/popup-style" UI requirement.
MAIN_APP_CLASS = "dev.ash.PasswordManager"
LOCKED_APP_CLASS = "dev.ash.PasswordManager.Locked"
SETUP_APP_CLASS = "dev.ash.PasswordManager.Setup"
LOGIN_APP_CLASS = "dev.ash.PasswordManager.Login"

# The new multi-vault flow's own app-ids never had a floating-window
# rule wired up anywhere -- write_persistent_include() below (the
# legacy include-file mechanism) only ever covered MAIN_APP_CLASS and
# LOCKED_APP_CLASS, and nothing in ui/setup, ui/login, or launcher/
# ash_daemon.py ever called it. Confirmed live: these windows tiled
# normally instead of floating. ensure_windows_float() covers all four.
ALL_APP_CLASSES = (SETUP_APP_CLASS, LOGIN_APP_CLASS, MAIN_APP_CLASS, LOCKED_APP_CLASS)


def is_available() -> bool:
    return shutil.which("hyprctl") is not None


def _hyprctl_eval(lua_code: str) -> bool:
    """Runs one `hyprctl eval` call. Only ever reports True when the
    process both exited 0 AND printed exactly "ok" -- on this
    Hyprland version a genuine failure exits non-zero with an "error:
    ..." line (confirmed live: an invalid dispatcher or an unparseable
    key string both produce exit code 7), so this alone is already a
    meaningfully stronger signal than the old `keyword` mechanism's
    always-0 exit code. It is still deliberately not trusted alone --
    see `register_runtime_bind`'s follow-up `hyprctl binds -j` check."""
    try:
        result = subprocess.run(
            ["hyprctl", "eval", lua_code], capture_output=True, timeout=5, check=False
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0 and result.stdout.decode("utf-8", errors="replace").strip() == "ok"


def _bind_is_registered(mods: str, key: str) -> bool:
    """Independently re-queries the compositor's own live bind table
    rather than trusting any command's reported exit status -- the
    entire reason this function exists is that the previous mechanism
    lied about success. Never raises: any inability to check reads as
    "not confirmed", which is the fail-closed direction here."""
    try:
        result = subprocess.run(["hyprctl", "binds", "-j"], capture_output=True, timeout=5, check=False)
        if result.returncode != 0:
            return False
        binds = json.loads(result.stdout.decode("utf-8", errors="replace"))
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
        return False
    expected_mask = _modmask_for(mods)
    return any(b.get("key") == key and b.get("modmask") == expected_mask for b in binds)


def register_runtime_bind(exec_cmd: str, mods: str = DEFAULT_MODS, key: str = DEFAULT_KEY) -> bool:
    """Register the shortcut for the *current* Hyprland session via IPC.
    Safe to call repeatedly (e.g. once per login/setup run).

    Uses `hyprctl eval "hl.bind(...)"` -- the current Hyprland Lua
    scripting API -- not the classic `hyprctl keyword bind` mechanism,
    which silently no-ops on this project's own development machine's
    installed Hyprland version (0.56.2): it exits 0 and prints
    "keyword can't work with non-legacy parsers. Use eval." without
    registering anything. Trusting that exit code was exactly the bug;
    this function never returns True without independently confirming
    the bind is actually present in `hyprctl binds -j` afterward, so a
    future Hyprland change that reintroduces a falsely-successful exit
    code cannot silently regress this again."""
    if not is_available():
        return False
    combo = "+".join(mods.split() + [key]) if mods.strip() else key
    lua = f"hl.bind({_lua_string_literal(combo)}, hl.dsp.exec_cmd({_lua_string_literal(exec_cmd)}))"
    if not _hyprctl_eval(lua):
        return False
    return _bind_is_registered(mods, key)


def ensure_windows_float(app_classes: tuple[str, ...] = ALL_APP_CLASSES) -> bool:
    """Applies a runtime "float, don't tile" rule for this app's window
    class(es), via the same `hyprctl eval "hl.window_rule(...)"`
    mechanism as `register_runtime_bind` -- confirmed against a real
    example already active in this project's own development
    environment (``~/.config/hypr/dms/windowrules.lua``:
    ``hl.window_rule({ match = { class = "..." }, float = true })``).
    Idempotent and safe to call every time a window is about to be
    shown: re-issuing an identical rule is harmless.

    Best-effort by design (matches this module's other runtime calls):
    callers should not treat a False return as fatal -- a tiled
    instead of floating window is a cosmetic issue, never a reason to
    block sign-in/login/setup. Returns False immediately, with no
    subprocess call at all, when hyprctl itself isn't available (e.g.
    a non-Hyprland session)."""
    if not is_available():
        return False
    ok = True
    for app_class in app_classes:
        escaped = app_class.replace(".", "\\.")
        pattern = f"^({escaped})$"
        lua = f"hl.window_rule({{ match = {{ class = {_lua_string_literal(pattern)} }}, float = true }})"
        ok = _hyprctl_eval(lua) and ok
    return ok


def hypr_config_dir() -> Path:
    import os

    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "hypr"


def _floating_window_rules() -> str:
    # Modern unified `windowrule` syntax (Hyprland consolidated
    # `windowrulev2` back into `windowrule` well before 0.56 -- using
    # the old name here would be exactly the "obsolete Hyprland syntax"
    # this project is required to avoid).
    return (
        f"windowrule = float, class:^({MAIN_APP_CLASS})$\n"
        f"windowrule = size 500 580, class:^({MAIN_APP_CLASS})$\n"
        f"windowrule = center, class:^({MAIN_APP_CLASS})$\n"
        f"windowrule = float, class:^({LOCKED_APP_CLASS})$\n"
        f"windowrule = size 380 220, class:^({LOCKED_APP_CLASS})$\n"
        f"windowrule = center, class:^({LOCKED_APP_CLASS})$\n"
    )


def write_persistent_include(exec_cmd: str, mods: str = DEFAULT_MODS, key: str = DEFAULT_KEY) -> Path:
    """Write a small standalone conf snippet the user can ``source`` from
    their own ``hyprland.conf``. Never modifies the user's own config
    file. Returns the path written."""
    d = hypr_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / INCLUDE_FILENAME
    bind_line = f"bind = {mods}, {key}, exec, {exec_cmd}\n"
    content = (
        "# Managed by password-manager setup. Safe to regenerate; do not\n"
        "# hand-edit (re-run `password-manager setup` instead).\n"
        f"{bind_line}"
        f"{_floating_window_rules()}"
    )
    path.write_text(content, encoding="utf-8")
    return path


def source_line_for(path: Path) -> str:
    return f"source = {path}"


def active_window_json() -> str | None:
    """Raw ``hyprctl activewindow -j`` output, used by
    ``core.auth.detection``. Kept here too (re-exported) so all Hyprland
    IPC calls live in one integration module."""
    if not is_available():
        return None
    try:
        result = subprocess.run(
            ["hyprctl", "activewindow", "-j"], capture_output=True, timeout=2, check=False
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return result.stdout.decode("utf-8", errors="replace")
