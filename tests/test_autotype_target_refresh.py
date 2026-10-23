"""Reopening an existing manager refreshes the external target before focus."""

import json
from types import SimpleNamespace

import pytest

from passman.core.auth.detection import DetectedContext


def test_sign_in_captures_target_before_focusing_existing_manager(monkeypatch):
    from passman.launcher import ash_daemon

    calls = []
    target = DetectedContext("browser", "Login", "0x111")
    monkeypatch.setattr(ash_daemon, "get_active_window_context", lambda: (calls.append("capture"), target)[1])
    monkeypatch.setattr(ash_daemon, "is_ui_running", lambda: True)
    monkeypatch.setattr(ash_daemon, "focus_existing", lambda ctx: calls.append(ctx))
    assert ash_daemon.run_sign_in_or_login() == 0
    assert calls == ["capture", target]


def test_focus_existing_sends_only_app_and_window_ids(monkeypatch):
    from passman.launcher import daemon

    calls = []
    monkeypatch.setattr(daemon, "send_command", lambda command: (calls.append(command), "ok")[1])
    assert daemon.focus_existing(DetectedContext("browser", "private page title", "0x111"))
    assert calls[0].startswith("focus-target ")
    assert json.loads(calls[0].partition(" ")[2]) == {"app_id": "browser", "window_id": "0x111"}
    assert "private page title" not in calls[0]


@pytest.mark.parametrize("own_window", [True, False])
def test_target_update_runs_on_ui_thread_and_preserves_external_target(monkeypatch, own_window):
    from passman.ui import app as mod

    queued, calls = [], []
    monkeypatch.setattr(mod.GLib, "idle_add", queued.append)
    previous = DetectedContext("browser", None, "0x111")
    app = SimpleNamespace(detected_context=previous, _present_window=lambda: calls.append("present"))
    app_id = "dev.ash.PasswordManager" if own_window else "other-app"
    result = mod.PasswordManagerApp._handle_focus_target_command(
        app, "focus-target " + json.dumps({"app_id": app_id, "window_id": "0x222"}),
    )
    assert result == "ok" and app.detected_context is previous and calls == []
    queued[0]()
    assert calls == ["present"]
    assert app.detected_context == (previous if own_window else DetectedContext(app_id, None, "0x222"))


@pytest.mark.parametrize("payload", ["not json", "[]", '{"app_id": 42}', '{"window_id": []}'])
def test_target_refresh_rejects_malformed_payload(monkeypatch, payload):
    from passman.ui import app as mod

    monkeypatch.setattr(mod.GLib, "idle_add", lambda _: pytest.fail("must not schedule invalid input"))
    assert mod.PasswordManagerApp._handle_focus_target_command(object(), "focus-target " + payload) == "invalid_target"
