"""New multi-vault entry point (spec sections 1, 18, 26, 27, 30):
Sign in / Login for the ``ash-password-manager`` CLI.

Reuses ``launcher.daemon``'s existing single-instance IPC check
(vault-agnostic -- it just asks "is *a* PasswordManagerApp already
running") and ``ui.app.run_main_app`` (which already accepts a
pre-unlocked vault handle, see ``ui/app.py``) -- only the "which
vault, and how do we get into it" decision is new. The legacy
single-vault ``run_show()`` in ``launcher/daemon.py`` is untouched and
still works exactly as it always did for anyone still using it.
"""

from __future__ import annotations

from ..core.auth.detection import DetectedContext, get_active_window_context
from ..core.flows.usb_login_lookup import find_and_mount_vault, find_connected_vault
from ..core.security.logging import get_logger, safe_extra
from ..core.vaults.registry import VaultRecord, load_vaults
from ..integration.hyprland import keybind as hypr_keybind
from ..ui.app import run_main_app
from .daemon import focus_existing, is_ui_running

_log = get_logger(__name__)


def run_sign_in_or_login() -> int:
    if is_ui_running():
        focus_existing()
        return 0

    # Best-effort, Hyprland-specific: none of this flow's windows
    # (Setup/Login/Manager/Locked) ever had a floating-window rule
    # wired up -- write_persistent_include() only ever covered the
    # legacy single-vault window, and nothing here called it. Confirmed
    # live: they tiled normally instead. Applied once, up front, since
    # Hyprland matches window rules by class at map time regardless of
    # which of this flow's several possible windows ends up shown.
    # Never blocks sign-in on failure -- a tiled window is cosmetic.
    hypr_keybind.ensure_windows_float()

    # Captured before any window exists, exactly like the legacy
    # run_show() -- see that function's docstring for why capturing it
    # any later would only ever see this app's own picker/manager
    # window and silently break suggestion ranking.
    detected_context = get_active_window_context()

    vaults = load_vaults()
    if not vaults:
        return _run_setup()

    match = find_connected_vault(vaults)
    if match is None:
        return _run_no_usb_window()

    record, mountpoint = match
    return _run_login(record, mountpoint, detected_context)


def _run_setup() -> int:
    from ..ui.setup import run_setup_wizard

    handle, record, mountpoint, discovered_existing = run_setup_wizard()

    if discovered_existing is not None:
        # The selected USB turned out to already have a real ASH vault
        # this device just isn't registered for yet (spec sections 5,
        # 13: a new device, or "recover") -- the wizard's job there is
        # done (it registered the vault locally); hand off to the
        # normal Login flow instead of trying to open a vault that was
        # never created.
        existing_record, existing_mountpoint = discovered_existing
        detected_context = get_active_window_context()
        return _run_login(existing_record, existing_mountpoint, detected_context)

    if handle is None or record is None or mountpoint is None:
        return 1
    return run_main_app(mountpoint, record, unlocked_vault=handle)


def _run_login(record: VaultRecord, mountpoint: str, detected_context: DetectedContext) -> int:
    from ..ui.login import run_login_window

    handle = run_login_window(record, mountpoint)
    if handle is None:
        _log.info("login window closed without unlocking", extra=safe_extra(event="login_cancelled"))
        return 1
    return run_main_app(mountpoint, record, detected_context, unlocked_vault=handle)


def _run_no_usb_window() -> int:
    from ..ui.locked_window import show_locked_window

    return show_locked_window("Connect a registered ASH Password Manager USB to continue.")


def main() -> None:
    raise SystemExit(run_sign_in_or_login())
