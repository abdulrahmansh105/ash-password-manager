"""Pure, GTK-free state machines for first-time setup and returning-
user login (spec sections 26, 27)."""

from __future__ import annotations

from .login_machine import (
    LoginFailureReason,
    LoginFlow,
    LoginOutcome,
    LoginState,
    attempt_automatic_login,
)
from .setup_machine import InvalidTransitionError, SetupDraft, SetupFlow, SetupState
from .usb_login_lookup import find_and_mount_vault, find_connected_vault
from .usb_setup import (
    SetupUsbError,
    UsbIdentity,
    detect_container_kind,
    pick_usable_block,
    prepare_mountpoint,
)

__all__ = [
    "InvalidTransitionError",
    "LoginFailureReason",
    "LoginFlow",
    "LoginOutcome",
    "LoginState",
    "SetupDraft",
    "SetupFlow",
    "SetupState",
    "SetupUsbError",
    "UsbIdentity",
    "attempt_automatic_login",
    "detect_container_kind",
    "find_and_mount_vault",
    "find_connected_vault",
    "pick_usable_block",
    "prepare_mountpoint",
]
