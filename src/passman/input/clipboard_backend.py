"""Opt-in clipboard-paste input backend.

Disabled unless the user has explicitly turned on "Allow clipboard
fallback" in Settings (spec section 16) -- that gate is enforced by the
caller (``core.auth.engine``), not here; this class will happily paste if
asked; it is the *selection* of this backend that must be gated.

Mechanism: copy the secret via ``wl-copy`` (reusing
``core.security.clipboard.ClipboardManager`` for its safe, generation-
tracked auto-clear behavior), then send Ctrl+V via the ydotool backend
(pasting still requires a synthetic keystroke -- there's no
clipboard-only way to get text into a focused field).
"""

from __future__ import annotations

from ..core.security.clipboard import ClipboardManager
from .backend import AuthInputBackend, BackendOutcome, InputResult
from .ydotool_backend import YdotoolBackend


class ClipboardPasteBackend(AuthInputBackend):
    name = "clipboard_paste"

    def __init__(self, clipboard: ClipboardManager | None = None, clear_after_seconds: int = 20) -> None:
        self._clipboard = clipboard or ClipboardManager()
        self._clear_after_seconds = clear_after_seconds
        self._paste_key_backend = YdotoolBackend()

    def is_available(self) -> bool:
        return ClipboardManager.is_available() and self._paste_key_backend.is_available()

    def type_text(self, secret: bytes) -> BackendOutcome:
        status = self._clipboard.copy(secret.decode("utf-8"), self._clear_after_seconds)
        if not status.copied:
            return BackendOutcome(InputResult.FAILED, "clipboard copy failed")
        outcome = self._paste_key_backend.press_combo("ctrl+v")
        if outcome.result != InputResult.OK:
            return outcome
        return BackendOutcome(InputResult.OK)

    def press_key(self, key: str) -> BackendOutcome:
        return self._paste_key_backend.press_key(key)

    def press_combo(self, combo: str) -> BackendOutcome:
        return self._paste_key_backend.press_combo(combo)
