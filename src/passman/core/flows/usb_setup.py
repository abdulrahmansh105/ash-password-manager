"""USB selection/unlock/mount orchestration for the first-run setup
wizard (spec section 2). The pure decision logic (picking which block
on a drive is the one to use) is separated from the live UDisks2/
udisksctl I/O so it is unit-testable with synthetic fixtures, matching
this project's existing pattern (``integration.usb.identity`` /
``integration.usb.udisks2``).

This module never handles a LUKS passphrase itself -- ``udisksctl
unlock`` owns that prompt directly (terminal or the desktop's polkit
agent), exactly as the rest of this project already guarantees (see
docs/THREAT_MODEL.md and ``tests/test_no_secret_persistence.py``'s
argv-shape assertions on ``integration.usb.udisks.unlock``).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..vaults.layout import DEFAULT_CONTAINER_DIRNAME, VaultLayout


class SetupUsbError(Exception):
    """User-facing: no secrets, no stack traces (spec section 25)."""


@dataclass(frozen=True)
class UsbIdentity:
    luks_uuid: str | None
    filesystem_uuid: str
    drive_vendor: str
    drive_model: str


def pick_usable_block(blocks: list) -> object | None:
    """``blocks`` is a list of ``integration.usb.udisks2.RawBlockInfo``.
    Prefers a block that is either an encrypted (LUKS) container or an
    already-formatted filesystem -- i.e. skips bare partition-table
    placeholders with no usage at all. Returns the first match; a
    multi-partition USB (uncommon for a single password vault) uses
    whichever partition UDisks2 lists first -- a known, disclosed
    simplification, not a silent guess."""
    for block in blocks:
        if block.id_usage in ("crypto", "filesystem"):
            return block
    return None


def prepare_mountpoint(drive_object_path: str, drive_vendor: str, drive_model: str) -> tuple[UsbIdentity, str]:
    """Unlocks (if the usable block is LUKS) and mounts the selected
    drive, returning its stable identity and the resulting mountpoint.
    Runs real, blocking I/O -- callers must run this off the GTK main
    thread (see ``ui.setup``, which wraps it in ``run_blocking_async``)."""
    from ...integration.usb import udisks2 as u2
    from ...integration.usb.udisks import mount as udisks_mount
    from ...integration.usb.udisks import unlock as udisks_unlock

    client = u2.new_client()
    _drives, blocks = u2.snapshot_from_client(client)
    my_blocks = [b for b in blocks if b.drive_object_path == drive_object_path]
    block = pick_usable_block(my_blocks)
    if block is None:
        raise SetupUsbError("No usable filesystem was found on this device.")

    luks_uuid: str | None = None
    target_block = block

    if block.id_usage == "crypto":
        luks_uuid = block.id_uuid
        if not udisks_unlock(block.device):
            raise SetupUsbError("Could not unlock this device -- wrong passphrase or cancelled.")
        _drives2, blocks2 = u2.snapshot_from_client(u2.new_client())
        cleartext = next((b for b in blocks2 if b.crypto_backing_device == block.object_path), None)
        if cleartext is None:
            raise SetupUsbError("Unlock succeeded but no filesystem was found inside.")
        target_block = cleartext

    mountpoint = target_block.mountpoints[0] if target_block.mountpoints else udisks_mount(target_block.device)
    if not mountpoint:
        raise SetupUsbError("Could not mount this device.")

    identity = UsbIdentity(
        luks_uuid=luks_uuid, filesystem_uuid=target_block.id_uuid, drive_vendor=drive_vendor, drive_model=drive_model
    )
    return identity, mountpoint


def detect_container_kind(mountpoint: str, container_rel_path: str) -> str:
    """Returns "ash" (already an ASH vault), "foreign" (a KDBX with no
    vault.json -- the adoption-offer branch, scoped to this selected,
    identified USB only per spec section 14), or "empty" (fresh)."""
    layout = VaultLayout.at(mountpoint, container_rel_path)
    if layout.exists():
        return "ash"
    if layout.is_legacy_kdbx_only():
        return "foreign"
    return "empty"


def discover_container(mountpoint: str) -> tuple[str, str]:
    """Finds the container to act on for a *selected, already-mounted*
    USB (spec section 14: this never browses anywhere else). Checks
    the default "ASH" container first (where every vault this
    application creates lives); if that is empty, scans the mount's
    top-level directories for an existing vault at some other path --
    e.g. a legacy single-vault registration's "Authentication/", or
    any other name a previous adoption used -- so a vault is found
    regardless of what its container happens to be named, without
    ever needing the user to type a path.

    Returns ``(container_rel_path, kind)``; ``kind`` is one of
    "ash"/"foreign"/"empty" (``detect_container_kind``'s vocabulary).
    The first non-"empty" match wins; if none is found anywhere,
    returns the default container name with kind "empty" (a fresh
    vault will be created there).
    """
    default_kind = detect_container_kind(mountpoint, DEFAULT_CONTAINER_DIRNAME)
    if default_kind != "empty":
        return DEFAULT_CONTAINER_DIRNAME, default_kind

    try:
        candidates = sorted(p.name for p in Path(mountpoint).iterdir() if p.is_dir() and p.name != DEFAULT_CONTAINER_DIRNAME)
    except OSError:
        candidates = []

    for name in candidates:
        kind = detect_container_kind(mountpoint, name)
        if kind != "empty":
            return name, kind

    return DEFAULT_CONTAINER_DIRNAME, "empty"
