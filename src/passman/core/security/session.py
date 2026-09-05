"""Vault session / lock state machine (spec section 6).

This is the single place that owns "is the vault currently unlocked" and
enforces that every lock trigger actually tears the session down the
same way: close the vault handle (best-effort wipe, see
``core.vault.kdbx.VaultHandle.close``), clear the clipboard if this app
put something there, invalidate the auth state, and notify subscribers
(the UI) to destroy sensitive widgets/state. No lock trigger is allowed
to bypass this -- there is exactly one ``lock()`` method.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from .clipboard import ClipboardManager
from .logging import get_logger, safe_extra

_log = get_logger(__name__)


class LockReason(Enum):
    STARTUP = "startup"
    USB_REMOVED = "usb_removed"
    SCREEN_LOCKED = "screen_locked"
    SUSPENDED = "suspended"
    INACTIVITY_TIMEOUT = "inactivity_timeout"
    MANUAL_CLOSE = "manual_close"
    VAULT_ERROR = "vault_error"


class SessionState(Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"


OnLockCallback = Callable[[LockReason], None]


@dataclass
class Session:
    """``vault`` is deliberately untyped here (kept as ``object``) so
    this module has no import-time dependency on pykeepass; it only
    needs ``.close()`` to exist, matching ``VaultHandle``."""

    inactivity_timeout_seconds: int = 300
    _state: SessionState = SessionState.LOCKED
    _vault: object | None = None
    _last_activity: float = 0.0
    _clipboard: ClipboardManager | None = None
    _on_lock: OnLockCallback | None = None

    def __post_init__(self) -> None:
        if self._clipboard is None:
            self._clipboard = ClipboardManager()

    def set_on_lock(self, callback: OnLockCallback | None) -> None:
        self._on_lock = callback

    @property
    def state(self) -> SessionState:
        return self._state

    def is_unlocked(self) -> bool:
        return self._state == SessionState.UNLOCKED

    def unlock(self, vault: object) -> None:
        self._vault = vault
        self._state = SessionState.UNLOCKED
        self.touch_activity()
        _log.info("session unlocked", extra=safe_extra(event="session_unlock"))

    def vault(self) -> object:
        if self._state != SessionState.UNLOCKED or self._vault is None:
            raise RuntimeError("Vault session is not unlocked.")
        return self._vault

    def touch_activity(self, now: float | None = None) -> None:
        self._last_activity = time.time() if now is None else now

    def seconds_since_activity(self, now: float | None = None) -> float:
        t = time.time() if now is None else now
        return t - self._last_activity

    def check_inactivity(self, now: float | None = None) -> bool:
        """Call periodically (e.g. every few seconds) from the UI's idle
        loop. Locks and returns True if the inactivity timeout has
        elapsed; a timeout of 0 disables this trigger."""
        if self._state != SessionState.UNLOCKED:
            return False
        if self.inactivity_timeout_seconds <= 0:
            return False
        if self.seconds_since_activity(now) >= self.inactivity_timeout_seconds:
            self.lock(LockReason.INACTIVITY_TIMEOUT)
            return True
        return False

    def lock(self, reason: LockReason) -> None:
        if self._state == SessionState.LOCKED:
            return
        vault = self._vault
        self._vault = None
        self._state = SessionState.LOCKED
        if vault is not None:
            try:
                vault.close()
            except Exception:  # noqa: BLE001 - lock must never fail to complete
                pass
        if self._clipboard is not None:
            self._clipboard.clear_now()
        _log.info("session locked", extra=safe_extra(event="session_lock", reason=reason.value))
        if self._on_lock is not None:
            self._on_lock(reason)
