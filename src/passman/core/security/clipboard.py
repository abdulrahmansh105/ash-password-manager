"""Wayland clipboard integration.

Ported from password-template-generator's ``ptgen.clipboard.manager``
(behavior unchanged) with one addition: this project defaults clipboard
usage to *off* everywhere it's used as an auth mechanism (spec section
16) -- that gating lives in the callers (``input.clipboard_backend``,
settings), not here; this class is just the safe copy/auto-clear
primitive either the password-generator UI or the opt-in autotype
clipboard backend can use.

Safety notes
------------
- The secret is handed to ``wl-copy`` and never written to disk or logged.
- Auto-clear only clears the clipboard if it still contains exactly what
  we put there. If the user (or another application) has copied
  something else in the meantime, we leave it alone.
- Each copy gets a monotonically increasing "generation" number; a clear
  callback that fires after a newer copy has happened is a no-op.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from dataclasses import dataclass


class ClipboardUnavailableError(Exception):
    """Raised when wl-copy/wl-paste are not available on this system."""


@dataclass
class ClipboardStatus:
    copied: bool
    error: str | None = None


class ClipboardManager:
    def __init__(self) -> None:
        self._generation = 0
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None

    @staticmethod
    def is_available() -> bool:
        return shutil.which("wl-copy") is not None and shutil.which("wl-paste") is not None

    def copy(self, text: str, timeout_seconds: int | None) -> ClipboardStatus:
        """Copy ``text`` to the clipboard.

        If ``timeout_seconds`` is a positive number, schedule a clear of
        the clipboard after that many seconds, but only if the clipboard
        still holds exactly what we copied.
        """
        if not self.is_available():
            return ClipboardStatus(
                copied=False,
                error="wl-clipboard (wl-copy/wl-paste) is not installed.",
            )

        with self._lock:
            self._generation += 1
            generation = self._generation
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

        try:
            subprocess.run(
                ["wl-copy"],
                input=text.encode("utf-8"),
                check=True,
                timeout=5,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return ClipboardStatus(copied=False, error=f"Failed to copy to clipboard: {type(exc).__name__}")

        if timeout_seconds and timeout_seconds > 0:
            timer = threading.Timer(
                timeout_seconds, self._clear_if_unchanged, args=(generation, text)
            )
            timer.daemon = True
            with self._lock:
                self._timer = timer
            timer.start()

        return ClipboardStatus(copied=True)

    def cancel_pending_clear(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def clear_now(self) -> None:
        """Force-clear the clipboard immediately (used on lock)."""
        self.cancel_pending_clear()
        try:
            subprocess.run(["wl-copy", "--clear"], timeout=5, check=False)
        except (subprocess.SubprocessError, OSError):
            pass

    def _clear_if_unchanged(self, generation: int, expected_text: str) -> None:
        with self._lock:
            if generation != self._generation:
                return
        try:
            result = subprocess.run(
                ["wl-paste", "-n"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            current = result.stdout.decode("utf-8", errors="replace")
        except (subprocess.SubprocessError, OSError):
            return

        if current != expected_text:
            return

        with self._lock:
            if generation != self._generation:
                return
        try:
            subprocess.run(["wl-copy", "--clear"], timeout=5, check=False)
        except (subprocess.SubprocessError, OSError):
            pass
