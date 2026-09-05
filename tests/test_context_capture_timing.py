"""Regression test for a real bug found during live Hyprland/DMS
validation: the active-window context must be captured once, before
the picker window ever takes focus -- not re-queried later, or the
Safety Guard and suggestion ranking would only ever see the picker's
own window. See launcher/daemon.py's run_show() docstring."""

from __future__ import annotations

from unittest.mock import patch

from passman.config.store import UsbRegistration
from passman.core.auth.detection import DetectedContext
from passman.launcher import daemon


def test_run_show_captures_context_before_checking_ui_running():
    call_order = []

    def fake_get_context():
        call_order.append("get_context")
        return DetectedContext(app_id="discord", window_title="Discord")

    def fake_is_ui_running():
        call_order.append("is_ui_running")
        return True

    def fake_focus_existing():
        call_order.append("focus_existing")
        return True

    with (
        patch.object(daemon, "get_active_window_context", fake_get_context),
        patch.object(daemon, "is_ui_running", fake_is_ui_running),
        patch.object(daemon, "focus_existing", fake_focus_existing),
    ):
        daemon.run_show()

    assert call_order[0] == "get_context"  # captured before anything else


def test_run_show_passes_captured_context_to_run_main_app(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    captured_context = DetectedContext(app_id="my-target-app", window_title="Login")

    from passman.config import store as store_mod

    reg = UsbRegistration(luks_uuid="x", filesystem_uuid="y")
    store_mod.save_usb_registration(reg)

    received = {}

    def fake_run_main_app(mountpoint, registration, detected_context=None):
        received["mountpoint"] = mountpoint
        received["detected_context"] = detected_context
        return 0

    with (
        patch.object(daemon, "get_active_window_context", lambda: captured_context),
        patch.object(daemon, "is_ui_running", lambda: False),
        patch.object(daemon, "list_block_devices", lambda: []),
        patch(
            "passman.ui.app.run_main_app",
            fake_run_main_app,
        ),
    ):
        # Force a MOUNTED status so run_show reaches run_main_app.
        from passman.integration.usb.identity import UsbState, UsbStatus

        with patch.object(daemon, "evaluate_usb_status", lambda devices, r: UsbStatus(state=UsbState.MOUNTED, mountpoint=str(tmp_path))):
            daemon.run_show()

    assert received["detected_context"] is captured_context
