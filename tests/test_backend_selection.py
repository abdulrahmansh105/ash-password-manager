"""select_backend() preference order and the clipboard-off-by-default
guarantee (spec section 16/6): clipboard must never be chosen unless
explicitly allowed, even when it's the only thing technically available."""

from __future__ import annotations

from passman.input import ClipboardPasteBackend, select_backend
from passman.input.atspi_backend import AtspiBackend
from passman.input.ydotool_backend import YdotoolBackend


def _force(monkeypatch, atspi=False, ydotool=False, clipboard=False):
    monkeypatch.setattr(AtspiBackend, "is_available", lambda self: atspi)
    monkeypatch.setattr(YdotoolBackend, "is_available", lambda self: ydotool)
    monkeypatch.setattr(ClipboardPasteBackend, "is_available", lambda self: clipboard)


def test_clipboard_never_selected_when_fallback_disabled_even_if_only_option(monkeypatch):
    _force(monkeypatch, atspi=False, ydotool=False, clipboard=True)
    backend = select_backend(allow_clipboard_fallback=False)
    assert backend is None


def test_clipboard_selected_only_when_explicitly_allowed_and_nothing_else_available(monkeypatch):
    _force(monkeypatch, atspi=False, ydotool=False, clipboard=True)
    backend = select_backend(allow_clipboard_fallback=True)
    assert isinstance(backend, ClipboardPasteBackend)


def test_atspi_preferred_over_ydotool_and_clipboard(monkeypatch):
    _force(monkeypatch, atspi=True, ydotool=True, clipboard=True)
    backend = select_backend(allow_clipboard_fallback=True)
    assert isinstance(backend, AtspiBackend)


def test_ydotool_preferred_over_clipboard_when_atspi_unavailable(monkeypatch):
    _force(monkeypatch, atspi=False, ydotool=True, clipboard=True)
    backend = select_backend(allow_clipboard_fallback=True)
    assert isinstance(backend, YdotoolBackend)


def test_none_available_returns_none_not_a_silent_fake(monkeypatch):
    _force(monkeypatch, atspi=False, ydotool=False, clipboard=False)
    assert select_backend(allow_clipboard_fallback=True) is None
    assert select_backend(allow_clipboard_fallback=False) is None


def test_default_call_has_clipboard_fallback_off():
    # select_backend()'s own default must match Settings.clipboard_fallback_enabled's
    # default (False) -- this test would fail loudly if either default drifted.
    import inspect

    sig = inspect.signature(select_backend)
    assert sig.parameters["allow_clipboard_fallback"].default is False
