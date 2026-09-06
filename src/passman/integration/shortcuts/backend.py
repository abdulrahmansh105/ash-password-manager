"""Shared shortcut-backend contract (spec section 9), mirroring
``input/backend.py``'s existing ``AuthInputBackend`` idiom: an ABC
plus a small result type, one concrete module per backend, and a
preference-ordered ``select_backend()`` in ``__init__.py``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class BindResult(Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    CONFLICT = "conflict"
    FAILED = "failed"


@dataclass(frozen=True)
class BindOutcome:
    result: BindResult
    detail: str = ""


class ShortcutBackend(ABC):
    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def bind(self, accelerator: str, exec_cmd: str, description: str) -> BindOutcome:
        """Register ``accelerator`` (GTK accelerator syntax, e.g.
        ``"<Ctrl><Alt>p"``) to run ``exec_cmd``. Must never silently
        replace an existing, different user-defined binding on the
        same accelerator (spec section 9) -- return ``BindResult.
        CONFLICT`` instead."""

    def reapply_on_startup(self, accelerator: str, exec_cmd: str, description: str) -> None:
        """Called once by the background agent at login/startup for
        backends whose binding does not otherwise persist across a
        compositor restart (see ``hyprland.py``). A no-op default is
        correct for backends that persist on their own (portal,
        gsettings, kwriteconfig)."""
        return

    def conflicts_with_existing(self, accelerator: str) -> str | None:
        """Returns a human-readable description of what already owns
        this accelerator, or None if it's free. Default: unknown
        (best-effort only; not every backend can introspect this)."""
        return None
