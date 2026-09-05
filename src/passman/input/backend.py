"""Abstraction over Wayland-compatible synthetic input mechanisms.

``AuthInputBackend`` is the contract the login-strategy executor
(``core.auth.engine``) codes against. Nothing above this layer knows or
cares whether a keystroke was delivered via AT-SPI, ydotool, or a
clipboard paste -- that decision is made per-call by
``select_backend()`` based on what's available and what the target
supports.

Hard rule enforced by every implementation: secret text is never passed
as a subprocess *argument* (visible in ``ps``/``/proc/<pid>/cmdline`` to
any local user) and never logged. It is passed via stdin or an in-process
API call instead.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class InputResult(Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


@dataclass(frozen=True)
class BackendOutcome:
    result: InputResult
    detail: str = ""  # non-secret, safe-to-log/display status text only


class AuthInputBackend(ABC):
    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        """Cheap, side-effect-free check (binary present, service
        reachable, etc.). Must never require the secret to check."""

    @abstractmethod
    def type_text(self, secret: bytes) -> BackendOutcome:
        """Deliver ``secret`` (utf-8 bytes) as keystrokes / field content
        to the currently focused input target. Callers must wipe
        ``secret`` themselves immediately after this returns."""

    @abstractmethod
    def press_key(self, key: str) -> BackendOutcome:
        """Press a single named key: ``tab``, ``enter``, ``escape``."""

    @abstractmethod
    def press_combo(self, combo: str) -> BackendOutcome:
        """Press a key combination, e.g. ``ctrl+a``, ``ctrl+v``."""

    def focus_field(self, hint: str | None) -> BackendOutcome:
        """Optional: move focus to a field matching ``hint`` (e.g.
        "password") using structural information (AT-SPI role/name).
        Backends that can't do this (ydotool, clipboard) no-op as
        UNAVAILABLE rather than guessing -- the executor then falls back
        to keyboard navigation (Tab) instead."""
        return BackendOutcome(InputResult.UNAVAILABLE, "focus_field not supported by this backend")
