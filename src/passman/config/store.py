"""Local, non-sensitive configuration storage.

Only settings and the USB *registration record* (stable hardware
identifiers -- LUKS UUID, filesystem UUID, relative paths -- none of
which are secret by themselves) are ever written here. No password, key
file content, TOTP secret, or recovery code is ever persisted by this
module; those live only inside the KDBX vault on the USB (see
``core.vault.kdbx``).

Ported pattern from password-template-generator's ``ptgen.config.store``:
atomic writes, 0700 dir / 0600 file permissions, tolerant reload of
corrupt/missing files back to defaults.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from ..core.appdirs import (
    config_home,
    legacy_config_home,
    migrate_legacy_config_if_needed,
)

DIR_MODE = 0o700
FILE_MODE = 0o600

CONFIG_SCHEMA_VERSION = 2


def config_dir() -> Path:
    """The app's local config directory (spec sections 17/19/31's
    rebrand to "ASH Password Manager"): now
    ``~/.config/ash-password-manager`` (see ``core.appdirs``), with a
    one-time, copy-only migration of ``settings.json`` from the
    pre-rebrand ``~/.config/password-manager`` the first time this is
    called in a given environment. The legacy directory is never
    modified -- see ``core.appdirs.migrate_legacy_config_if_needed``'s
    docstring."""
    migrate_legacy_config_if_needed()
    return config_home()


CLIPBOARD_TIMEOUT_CHOICES = {"never": None, "15s": 15, "30s": 30, "60s": 60, "5m": 300}
DEFAULT_CLIPBOARD_TIMEOUT_KEY = "30s"

SAFETY_GUARD_CHOICES = ("auto_high_confidence", "always_confirm")
THEME_CHOICES = ("ash", "dms", "dark", "light")  # "ash" = the brand palette (default); "dms" = follow system/DMS
USB_REMOVAL_CHOICES = ("lock_immediately", "keep_unlocked")
DEFAULT_USB_REMOVAL_ACTION = "lock_immediately"


@dataclass
class Settings:
    schema_version: int = CONFIG_SCHEMA_VERSION

    # General
    theme: str = "ash"
    ui_density: str = "comfortable"  # "comfortable" | "compact"

    # Security
    inactivity_timeout_seconds: int = 300
    auto_lock_enabled: bool = True
    lock_on_screen_lock: bool = True
    lock_on_suspend: bool = True
    lock_on_usb_removal: bool = True
    usb_removal_action: str = DEFAULT_USB_REMOVAL_ACTION
    usb_removal_explained: bool = False  # spec section 10: show the explanation once before first letting the user configure this
    clipboard_fallback_enabled: bool = False
    clipboard_timeout_key: str = DEFAULT_CLIPBOARD_TIMEOUT_KEY

    # Shortcuts (spec section 9)
    hotkey_accelerator: str = ""  # empty = not yet configured; never silently defaulted once the user has chosen one
    hotkey_backend: str = ""  # "portal" | "hyprland" | "gnome" | "kde" | "sway" | "manual"

    # Authentication (autotype -- spec section 34 decision: kept as an advanced feature only)
    typing_delay_ms: int = 12
    key_delay_ms: int = 30
    totp_clock_drift_windows: int = 1
    login_step_timeout_ms: int = 4000
    login_retry_count: int = 1
    default_auth_strategy: str = "default"
    safety_guard_mode: str = "auto_high_confidence"

    # Accounts
    suggested_account_enabled: bool = True
    icon_cache_enabled: bool = True
    search_case_sensitive: bool = False

    # Background agent / installer (spec sections 18, 30)
    agent_autostart_enabled: bool = True
    bootstrap_installer_enabled: bool = False

    # Advanced
    diagnostic_mode: bool = False

    def clipboard_timeout_seconds(self) -> int | None:
        return CLIPBOARD_TIMEOUT_CHOICES.get(
            self.clipboard_timeout_key, CLIPBOARD_TIMEOUT_CHOICES[DEFAULT_CLIPBOARD_TIMEOUT_KEY]
        )

    def effective_auto_lock_timeout_seconds(self) -> int:
        """0 disables ``Session``'s inactivity trigger entirely -- see
        ``core.security.session.Session.check_inactivity``. Keeping
        the configured timeout value separate from the enabled flag
        means toggling Auto Lock off and back on remembers the user's
        chosen timeout instead of resetting it."""
        return self.inactivity_timeout_seconds if self.auto_lock_enabled else 0


@dataclass
class UsbRegistration:
    """Stable-identity record for the registered vault USB. No secret
    material -- UUIDs and relative paths only (spec section 4: never
    trust a mount path or a filesystem label alone)."""

    luks_uuid: str
    filesystem_uuid: str
    vault_rel_path: str = "Passwords.kdbx"
    keyfile_rel_path: str = "Key.key"
    label: str = ""  # informational only, never trusted for identity


def _ensure_dir(d: Path) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, DIR_MODE)
    except OSError:
        pass
    return d


def _ensure_config_dir() -> Path:
    return _ensure_dir(config_dir())


def _atomic_write_json(path: Path, data: Any, *, ensure_dir: Path | None = None) -> None:
    """``ensure_dir`` defaults to the (new) settings config directory
    -- pass the legacy directory explicitly for ``usb.json``, which
    stays in its original location (see ``load_usb_registration``'s
    docstring)."""
    _ensure_dir(ensure_dir) if ensure_dir is not None else _ensure_config_dir()
    tmp_path = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp_path, FILE_MODE)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return default


# --- settings.json ------------------------------------------------------


def _sanitize_types(cfg: Settings) -> Settings:
    """Reject any field whose loaded value's type doesn't exactly match
    its declared default's type (spec section 21's "validate all
    input", applied to local config as well as vault data) -- e.g. a
    hand-edited ``"inactivity_timeout_seconds": "not-a-number"`` must
    revert to the default instead of reaching ``Session(...)`` and
    raising on its first comparison. An exact ``type(...) is
    type(...)`` check (not ``isinstance``) deliberately treats ``bool``
    and ``int`` as distinct, since JSON booleans and numbers are
    different types and ``bool`` is otherwise a subclass of ``int``."""
    defaults = Settings()
    for f in fields(Settings):
        value = getattr(cfg, f.name)
        default = getattr(defaults, f.name)
        if type(value) is not type(default):
            setattr(cfg, f.name, default)
    return cfg


def load_settings() -> Settings:
    path = config_dir() / "settings.json"
    raw = _read_json(path, {})
    defaults = Settings()
    known = {f for f in defaults.__dataclass_fields__}
    filtered = {k: v for k, v in raw.items() if k in known}
    cfg = Settings(**{**asdict(defaults), **filtered})
    cfg = _sanitize_types(cfg)
    if cfg.theme not in THEME_CHOICES:
        cfg.theme = "ash"
    if cfg.clipboard_timeout_key not in CLIPBOARD_TIMEOUT_CHOICES:
        cfg.clipboard_timeout_key = DEFAULT_CLIPBOARD_TIMEOUT_KEY
    if cfg.safety_guard_mode not in SAFETY_GUARD_CHOICES:
        cfg.safety_guard_mode = "auto_high_confidence"
    if cfg.usb_removal_action not in USB_REMOVAL_CHOICES:
        cfg.usb_removal_action = DEFAULT_USB_REMOVAL_ACTION
    return cfg


def save_settings(cfg: Settings) -> None:
    _atomic_write_json(config_dir() / "settings.json", asdict(cfg))


# --- usb.json (legacy single-vault registration) --------------------------
#
# Deliberately kept in the pre-rebrand legacy directory
# (core.appdirs.legacy_config_home(), NOT config_dir()) rather than
# moved alongside settings.json: this is the original single-vault
# design's own registration record, still used unchanged by the
# original `password-manager setup`/`show`/`status`/`doctor` commands
# (spec section 34 decision: the legacy path stays fully working, not
# just "still present in the code"). Moving it here would have
# silently broken every existing registration the moment this rebrand
# shipped.
#
# core.vaults.registry deliberately does NOT read this file to seed
# the new multi-vault registry -- an earlier version did, and that
# silently blocked the Sign-in wizard's own adoption offer for anyone
# with a legacy registration (see that module's `load_vaults`
# docstring for the full story). The two registries stay independent:
# this file is legacy-CLI-only, `vaults.json` is new-flow-only, and
# the wizard's foreign-KDBX detection is the only sanctioned bridge
# between them.


def _legacy_usb_json_path() -> Path:
    return legacy_config_home() / "usb.json"


def load_usb_registration() -> UsbRegistration | None:
    raw = _read_json(_legacy_usb_json_path(), None)
    if not raw:
        return None
    try:
        return UsbRegistration(**{k: raw[k] for k in UsbRegistration.__dataclass_fields__ if k in raw})
    except (KeyError, TypeError):
        return None


def save_usb_registration(reg: UsbRegistration) -> None:
    _atomic_write_json(_legacy_usb_json_path(), asdict(reg), ensure_dir=legacy_config_home())


def clear_usb_registration() -> None:
    try:
        _legacy_usb_json_path().unlink()
    except FileNotFoundError:
        pass
