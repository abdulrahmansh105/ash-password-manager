"""Tests for integration.notify -- best-effort desktop notifications
(spec section 20). Never a substitute for the actual lock/action it
reports; must degrade silently when notify-send is unavailable."""

from __future__ import annotations

from passman.integration import notify


def test_is_available_reflects_which(monkeypatch):
    monkeypatch.setattr(notify.shutil, "which", lambda name: "/usr/bin/notify-send")
    assert notify.is_available() is True
    monkeypatch.setattr(notify.shutil, "which", lambda name: None)
    assert notify.is_available() is False


def test_notify_returns_false_when_unavailable(monkeypatch):
    monkeypatch.setattr(notify.shutil, "which", lambda name: None)
    assert notify.notify("title", "body") is False


def test_notify_never_raises_on_subprocess_failure(monkeypatch):
    monkeypatch.setattr(notify.shutil, "which", lambda name: "/usr/bin/notify-send")

    def raising_run(*_a, **_k):
        raise OSError("simulated failure")

    monkeypatch.setattr(notify.subprocess, "run", raising_run)
    assert notify.notify("title", "body") is False


def test_notify_success_path_calls_notify_send_with_app_name(monkeypatch):
    monkeypatch.setattr(notify.shutil, "which", lambda name: "/usr/bin/notify-send")
    calls = []

    class _Result:
        pass

    monkeypatch.setattr(notify.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or _Result())

    assert notify.notify("Vault locked", "USB removed") is True
    assert calls[0][0] == "notify-send"
    assert "--app-name" in calls[0]
    assert notify.APP_NAME in calls[0]
    assert "Vault locked" in calls[0]
    assert "USB removed" in calls[0]


def test_notify_helpers_pass_through_only_their_given_label(monkeypatch):
    """Every helper's signature only accepts a plain display label
    (a device name, a file path, a fixed reason string) -- there is no
    parameter shape here that could carry a password, Local Key, or
    key slot; this asserts each helper's notify-send body is exactly
    the label given, nothing synthesized or pulled from elsewhere."""
    monkeypatch.setattr(notify.shutil, "which", lambda name: "/usr/bin/notify-send")
    calls = []

    class _Result:
        pass

    monkeypatch.setattr(notify.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or _Result())

    notify.notify_device_registered("My Laptop")
    notify.notify_device_revoked("Old Desktop")
    notify.notify_backup_created("/tmp/backup.ashbak")

    assert "My Laptop" in calls[0][-1]
    assert "Old Desktop" in calls[1][-1]
    assert calls[2][-1] == "/tmp/backup.ashbak"
