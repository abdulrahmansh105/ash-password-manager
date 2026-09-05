"""Central XDG path resolution for ASH Password Manager, plus the
one-time legacy-config migration from the pre-rebrand ``password-
manager`` config directory (spec sections 17/19/31: rebrand to "ASH
Password Manager" without silently losing anyone's existing local
settings).

Every module that needs a local (non-vault) storage location imports
from here, so there is exactly one definition of "where does this
app's local data live" in the whole project. The internal Python
package remains ``passman`` and the Wayland app-id remains
``dev.ash.PasswordManager`` (existing window rules depend on it) --
only the user-visible CLI name and on-disk config directory change.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

APP_DIRNAME = "ash-password-manager"
LEGACY_APP_DIRNAME = "password-manager"

_MIGRATABLE_FILENAMES = ("settings.json", "strategy_presets.json")


def _xdg(env_var: str, fallback: Path) -> Path:
    value = os.environ.get(env_var)
    return Path(value) if value else fallback


def config_home() -> Path:
    return _xdg("XDG_CONFIG_HOME", Path.home() / ".config") / APP_DIRNAME


def legacy_config_home() -> Path:
    return _xdg("XDG_CONFIG_HOME", Path.home() / ".config") / LEGACY_APP_DIRNAME


def data_home() -> Path:
    return _xdg("XDG_DATA_HOME", Path.home() / ".local" / "share") / APP_DIRNAME


def state_home() -> Path:
    return _xdg("XDG_STATE_HOME", Path.home() / ".local" / "state") / APP_DIRNAME


def runtime_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(base) / APP_DIRNAME


def migrate_legacy_config_if_needed() -> bool:
    """Best-effort, idempotent, copy-only migration of
    ``settings.json``/``strategy_presets.json`` from the legacy config
    directory into the new one. Never touches, moves, or deletes
    anything in the legacy directory -- if the new location ever turns
    out to be wrong, nothing has been destroyed. ``usb.json`` is
    deliberately not handled here: converting a single legacy USB
    registration into a ``VaultRecord`` needs real domain logic (a
    fresh vault id, deciding the container path), which lives in
    ``core.vaults.registry`` instead.

    Naturally idempotent without any process-global state: once the
    new directory exists, this always returns False immediately, which
    also keeps it safe to call from tests that each use their own
    isolated ``XDG_CONFIG_HOME``.
    """
    new_dir = config_home()
    old_dir = legacy_config_home()
    if new_dir.exists() or not old_dir.exists():
        return False

    new_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(new_dir, 0o700)
    except OSError:
        pass

    migrated = False
    for name in _MIGRATABLE_FILENAMES:
        src = old_dir / name
        if not src.exists():
            continue
        try:
            dst = new_dir / name
            shutil.copy2(src, dst)
            os.chmod(dst, 0o600)
            migrated = True
        except OSError:
            pass
    return migrated
