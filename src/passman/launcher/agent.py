"""Background USB-watch agent (spec section 30): a minimal, resident
process whose only job is noticing when a *registered* ASH vault's USB
appears and then spawning the normal ``ash-password-manager sign-in``
CLI command -- exactly the same command the hotkey runs. It holds no
vault handle and no secrets at any point.

This is a disclosed, deliberate exception to this project's original
"nothing resident while locked" stance (see docs/THREAT_MODEL.md) --
spec section 30 explicitly requires monitoring removable-media events,
which is not possible without something running continuously. The
trade-off is written down rather than silently introduced: an attacker
who compromises this process gains the ability to *spawn the sign-in
UI*, nothing more -- it never touches a key, a slot, or the vault
itself, so compromising it does not expose any secret this process
never held in the first place.

Duplicate-popup avoidance (spec section 30: "do not open multiple
popups for the same USB insertion event") is edge-triggered here
(spawn only on a registered vault's not-connected -> connected
transition) *and* enforced again, independently, by the spawned CLI
process itself via the existing single-instance IPC check in
``launcher.daemon``/``launcher.ash_daemon`` -- so even a burst of
redundant spawns (e.g. two vaults on one hub appearing together) can
never open two windows.
"""

from __future__ import annotations

import subprocess
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib  # noqa: E402

from ..core.security.logging import get_logger, safe_extra
from ..core.vaults.registry import load_vaults
from ..integration.usb.udisks2 import Udisks2Monitor, Udisks2Unavailable, new_client, snapshot_from_client
from .usb_watch_logic import compute_newly_connected_vaults

_log = get_logger(__name__)
_SIGN_IN_CMD = ["ash-password-manager", "sign-in"]


class UsbWatchAgent:
    def __init__(self) -> None:
        self._monitor = Udisks2Monitor(self._on_devices_changed)
        self._previously_connected: set[str] = set()

    def start(self) -> bool:
        if not self._monitor.start():
            _log.warning("UDisks2 unavailable; agent cannot watch for USB events", extra=safe_extra(event="agent_no_udisks2"))
            return False
        self._reapply_hotkey()
        self._poll_once()
        return True

    def _reapply_hotkey(self) -> None:
        from ..config.store import load_settings
        from ..integration.shortcuts import available_backends

        settings = load_settings()
        if not settings.hotkey_accelerator or not settings.hotkey_backend:
            return
        for backend in available_backends():
            if backend.name == settings.hotkey_backend:
                try:
                    backend.reapply_on_startup(settings.hotkey_accelerator, "ash-password-manager sign-in", "Open ASH Password Manager")
                except Exception:  # noqa: BLE001 - a failed reapply must not crash the agent
                    _log.warning("hotkey reapply failed", extra=safe_extra(event="agent_hotkey_reapply_failed"))
                break

    def _poll_once(self) -> None:
        try:
            client = new_client()
            _drives, blocks = snapshot_from_client(client)
        except Udisks2Unavailable:
            return
        self._handle_blocks(blocks)

    def _on_devices_changed(self, _devices) -> None:
        # _devices is the BlockDevice tree (identity.py shape); re-fetch
        # the raw UDisks2 snapshot directly here since
        # find_and_mount_vault needs RawBlockInfo, not that tree.
        self._poll_once()

    def _handle_blocks(self, blocks) -> None:
        from ..core.flows.usb_login_lookup import find_and_mount_vault

        vaults = load_vaults()
        currently_connected = set()
        for record in vaults:
            if find_and_mount_vault(record) is not None:
                currently_connected.add(record.vault_id)

        newly_connected = compute_newly_connected_vaults(self._previously_connected, currently_connected)
        self._previously_connected = currently_connected

        for vault_id in newly_connected:
            _log.info("registered vault USB connected", extra=safe_extra(event="agent_vault_connected", vault_id=vault_id))
            self._spawn_sign_in()

    def _spawn_sign_in(self) -> None:
        try:
            subprocess.Popen(_SIGN_IN_CMD, start_new_session=True)  # noqa: S603 - fixed argv, no user input
        except OSError:
            _log.warning("could not spawn sign-in", extra=safe_extra(event="agent_spawn_failed"))

    def stop(self) -> None:
        self._monitor.stop()


def run_agent() -> int:
    app = Adw.Application(application_id="dev.ash.PasswordManager.Agent")
    agent = UsbWatchAgent()

    def on_activate(_app) -> None:
        app.hold()  # keep running with no window
        if not agent.start():
            print("error: UDisks2 is not available; the agent cannot watch for USB events.", file=sys.stderr)
            app.quit()

    app.connect("activate", on_activate)
    try:
        return app.run(None)
    finally:
        agent.stop()
