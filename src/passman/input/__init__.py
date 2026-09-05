from .atspi_backend import AtspiBackend
from .backend import AuthInputBackend, BackendOutcome, InputResult
from .clipboard_backend import ClipboardPasteBackend
from .ydotool_backend import YdotoolBackend


def select_backend(
    allow_clipboard_fallback: bool = False,
) -> AuthInputBackend | None:
    """Pick the best available backend, in preference order:
    AT-SPI (structural, safest) > ydotool (global synthetic input) >
    clipboard paste (only if explicitly allowed). Returns ``None`` if
    nothing is available -- callers must surface a non-sensitive failure
    message (spec section 30), never fall back to silently doing
    nothing that looks like it worked."""
    atspi = AtspiBackend()
    if atspi.is_available():
        return atspi
    ydotool = YdotoolBackend()
    if ydotool.is_available():
        return ydotool
    if allow_clipboard_fallback:
        clip = ClipboardPasteBackend()
        if clip.is_available():
            return clip
    return None


__all__ = [
    "AtspiBackend",
    "AuthInputBackend",
    "BackendOutcome",
    "ClipboardPasteBackend",
    "InputResult",
    "YdotoolBackend",
    "select_backend",
]
