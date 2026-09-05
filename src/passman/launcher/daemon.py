"""The small host-side launcher (spec section 3).

Deliberately NOT a persistent background daemon: Hyprland's own
``bind = ...,exec,<cmd>`` model already re-execs this on every SUPER+CTRL+A
press, so there is nothing useful for a resident process to do while
idle -- keeping it non-resident is a smaller, simpler attack surface
(nothing at all runs, holds memory, or could be attacked while the vault
is locked and no window is open). See docs/THREAT_MODEL.md for why this
is a deliberate deviation from a literal reading of "small resident
agent" -- every functional requirement (react to shortcut, detect USB,
detect unlock state, show the UI or a locked message, never hold
secrets) is met without one.

This module contains NO password, TOTP secret, recovery code, or Key
File content at any point -- it only ever handles USB *identity*
(UUIDs) and filesystem paths.
"""

from __future__ import annotations

import sys

from ..config.store import load_usb_registration
from ..core.auth.detection import get_active_window_context
from ..integration.hyprland.keybind import register_runtime_bind
from ..integration.usb.identity import UsbState, evaluate_usb_status
from ..integration.usb.udisks import UdisksError, list_block_devices, mount as udisks_mount
from .ipc import send_command

SHOW_COMMAND = "password-manager show"


def is_ui_running() -> bool:
    return send_command("ping") == "pong"


def focus_existing() -> bool:
    return send_command("focus") == "ok"


def run_show(argv: list[str] | None = None) -> int:
    """Entry point for both ``password-manager show`` and the
    ``password-manager-launcher`` binary -- what SUPER+CTRL+A execs.

    Captures the active-window context as the very first thing this
    function does, before anything else runs (USB checks, vault open,
    window creation) and definitely before the picker itself ever gets
    focus. This matters: once the picker window is shown, IT becomes
    the active window, so capturing context any later than this would
    always see the picker's own window, never the app the user actually
    invoked the shortcut from -- which would silently break both
    suggested-account ranking and the Safety Guard's confidence check
    (discovered live, during Hyprland/DMS validation, not by unit tests,
    which construct ``DetectedContext`` directly and never exercise this
    timing at all)."""
    detected_context = get_active_window_context()

    if is_ui_running():
        if focus_existing():
            return 0

    reg = load_usb_registration()
    if reg is None:
        from ..ui.app import run_setup_window

        return run_setup_window()

    try:
        devices = list_block_devices()
    except UdisksError:
        from ..ui.locked_window import show_locked_window

        return show_locked_window(reason="USB detection unavailable on this system.")

    status = evaluate_usb_status(devices, reg)

    if status.state in (UsbState.ABSENT, UsbState.LOCKED, UsbState.IDENTITY_MISMATCH):
        from ..ui.locked_window import show_locked_window

        return show_locked_window(reason=_locked_reason(status.state))

    if status.state in (UsbState.UNLOCKED_NOT_MOUNTED, UsbState.PRESENT_NOT_MOUNTED) and status.mapped_device_path:
        mountpoint = udisks_mount(status.mapped_device_path)
        if mountpoint is None:
            from ..ui.locked_window import show_locked_window

            return show_locked_window(reason="Could not mount the vault USB.")
    elif status.state == UsbState.MOUNTED:
        mountpoint = status.mountpoint
    else:
        mountpoint = None

    if not mountpoint:
        from ..ui.locked_window import show_locked_window

        return show_locked_window(reason="Vault USB is not ready.")

    from ..ui.app import run_main_app

    return run_main_app(mountpoint=mountpoint, registration=reg, detected_context=detected_context)


def _locked_reason(state: UsbState) -> str:
    # User-facing text only -- never the vault path, key path, or any
    # implementation detail (spec section 25).
    if state == UsbState.IDENTITY_MISMATCH:
        return "This USB does not match your registered vault."
    return "Insert your USB key to continue."


def register_shortcut() -> bool:
    return register_runtime_bind(SHOW_COMMAND)


def main() -> None:
    sys.exit(run_show(sys.argv[1:]))


if __name__ == "__main__":
    main()
