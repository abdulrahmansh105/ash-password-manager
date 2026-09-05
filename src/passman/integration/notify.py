"""Desktop notifications (spec section 20). A thin wrapper around
``notify-send`` (the standard `org.freedesktop.Notifications` D-Bus
interface via the desktop-provided CLI, present on essentially every
Linux desktop) -- never required for correctness, only user feedback:
every call site already has a UI-visible result (a label, a toast) and
degrades silently to "no notification" if `notify-send` is missing.

Deliberately never includes secret material in a notification body --
every call site here passes only non-secret labels (a device name, a
vault name, a lock reason), matching this project's safe-logging
discipline (`core.security.logging`).
"""

from __future__ import annotations

import shutil
import subprocess

APP_NAME = "ASH Password Manager"


def is_available() -> bool:
    return shutil.which("notify-send") is not None


def notify(summary: str, body: str = "", *, urgency: str = "normal", icon: str = "dialog-password-symbolic") -> bool:
    """Best-effort only: returns False (never raises) if notify-send is
    missing or fails. ``urgency`` is one of "low"/"normal"/"critical"."""
    if not shutil.which("notify-send"):
        return False
    try:
        subprocess.run(
            ["notify-send", "--app-name", APP_NAME, "--icon", icon, "--urgency", urgency, summary, body],
            capture_output=True, timeout=5, check=False,
        )
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def notify_vault_locked(reason: str) -> bool:
    return notify("Vault locked", reason, urgency="normal", icon="channel-secure-symbolic")


def notify_device_registered(device_label: str) -> bool:
    return notify("New device registered", f"{device_label!r} can now unlock this vault.", icon="computer-symbolic")


def notify_device_revoked(device_label: str) -> bool:
    return notify(
        "Device revoked", f"{device_label!r} can no longer unlock this vault.",
        urgency="normal", icon="channel-secure-symbolic",
    )


def notify_backup_created(path: str) -> bool:
    return notify("Backup created", path, icon="document-save-symbolic")


def notify_usb_removed() -> bool:
    return notify("USB removed", "The vault was locked automatically.", icon="drive-removable-media-symbolic")
