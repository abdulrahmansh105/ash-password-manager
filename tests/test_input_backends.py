"""Input backend tests, all against mocked subprocess calls -- no real
ydotoold/AT-SPI bus touched. The critical property under test: a secret
never appears as a subprocess *argument* (spec section 31/32 -- never in
process arguments), only ever via stdin."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from passman.input.backend import InputResult
from passman.input.clipboard_backend import ClipboardPasteBackend
from passman.input.ydotool_backend import YdotoolBackend

FAKE_SECRET = b"fake-super-secret-password-xyz"


def _fake_completed(returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=b"", stderr=b"")


def test_ydotool_type_never_passes_secret_as_argv(monkeypatch):
    captured = {}

    def fake_run(args, input=None, **kwargs):  # noqa: A002
        captured["args"] = args
        captured["input"] = input
        return _fake_completed(0)

    monkeypatch.setattr("passman.input.ydotool_backend.subprocess.run", fake_run)
    backend = YdotoolBackend()
    outcome = backend.type_text(FAKE_SECRET)

    assert outcome.result == InputResult.OK
    assert captured["input"] == FAKE_SECRET
    joined_argv = " ".join(str(a) for a in captured["args"])
    assert FAKE_SECRET.decode() not in joined_argv


def test_ydotool_type_settles_before_returning(monkeypatch):
    # Regression test for a real race condition found during live
    # Hyprland testing: a `key` call issued immediately after `type`
    # can overtake it at the ydotoold level, corrupting the typed text
    # (a 19-character username arrived as a single stray character).
    # type_text() must sleep briefly before returning OK.
    monkeypatch.setattr("passman.input.ydotool_backend.subprocess.run", lambda *a, **kw: _fake_completed(0))
    slept = []
    monkeypatch.setattr("passman.input.ydotool_backend.time.sleep", lambda s: slept.append(s))
    backend = YdotoolBackend()
    outcome = backend.type_text(FAKE_SECRET)
    assert outcome.result == InputResult.OK
    assert slept and slept[0] > 0


def test_ydotool_type_reports_failed_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr("passman.input.ydotool_backend.subprocess.run", lambda *a, **kw: _fake_completed(1))
    backend = YdotoolBackend()
    outcome = backend.type_text(FAKE_SECRET)
    assert outcome.result == InputResult.FAILED
    assert FAKE_SECRET.decode() not in outcome.detail


def test_ydotool_press_key_unknown_name_fails_cleanly():
    backend = YdotoolBackend()
    outcome = backend.press_key("not-a-real-key")
    assert outcome.result == InputResult.FAILED


def test_ydotool_press_combo_sends_press_then_release(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        return _fake_completed(0)

    monkeypatch.setattr("passman.input.ydotool_backend.subprocess.run", fake_run)
    backend = YdotoolBackend()
    outcome = backend.press_combo("ctrl+v")
    assert outcome.result == InputResult.OK
    # ctrl down, v down, v up, ctrl up (reverse release order)
    assert captured["args"][-4:] == ["29:1", "47:1", "47:0", "29:0"]


def test_ydotool_unavailable_when_binary_missing(monkeypatch):
    monkeypatch.setattr("passman.input.ydotool_backend.shutil.which", lambda _n: None)
    backend = YdotoolBackend()
    assert backend.is_available() is False


def test_clipboard_backend_never_available_when_wl_copy_missing(monkeypatch):
    monkeypatch.setattr("passman.core.security.clipboard.ClipboardManager.is_available", staticmethod(lambda: False))
    backend = ClipboardPasteBackend()
    assert backend.is_available() is False
