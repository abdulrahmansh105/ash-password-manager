"""Given an already-registered ``VaultRecord``, find its matching
connected USB device (if any) and mount it (spec sections 1, 27, 30).

Deliberately narrow: ``udisksctl unlock`` (which can show a passphrase
prompt) is only ever attempted once a block device with the *exact*
registered LUKS UUID has actually been found connected -- never
speculatively for every registered vault on every USB-insertion event.
A vault whose USB is not currently connected returns ``None`` cleanly;
callers use that to distinguish "show the login window" from "prompt
the user to connect their USB" (spec section 25's missing-USB error
state), never to loop or retry unprompted.
"""

from __future__ import annotations

from ...integration.usb import udisks2 as u2
from ...integration.usb.udisks import mount as udisks_mount, unlock as udisks_unlock
from ..vaults.registry import VaultRecord


def find_and_mount_vault(record: VaultRecord) -> str | None:
    client = u2.new_client()
    _drives, blocks = u2.snapshot_from_client(client)

    if record.luks_uuid:
        luks_block = next((b for b in blocks if b.id_usage == "crypto" and b.id_uuid == record.luks_uuid), None)
        if luks_block is None:
            return None  # this vault's USB is not currently connected
        cleartext = next((b for b in blocks if b.crypto_backing_device == luks_block.object_path), None)
        if cleartext is None:
            if not udisks_unlock(luks_block.device):
                return None
            _drives2, blocks2 = u2.snapshot_from_client(u2.new_client())
            cleartext = next((b for b in blocks2 if b.crypto_backing_device == luks_block.object_path), None)
            if cleartext is None:
                return None
        if cleartext.id_uuid != record.filesystem_uuid:
            return None  # identity mismatch -- wrong inner filesystem; fail closed
        target = cleartext
    else:
        target = next((b for b in blocks if b.id_usage == "filesystem" and b.id_uuid == record.filesystem_uuid), None)
        if target is None:
            return None

    if target.mountpoints:
        return target.mountpoints[0]
    return udisks_mount(target.device)


def find_connected_vault(vaults: list[VaultRecord]) -> tuple[VaultRecord, str] | None:
    """Tries every registered vault in turn (spec section 16: multiple
    independently registered vaults) and returns the first one whose
    USB is actually connected right now, mounted and ready."""
    for record in vaults:
        mountpoint = find_and_mount_vault(record)
        if mountpoint is not None:
            return record, mountpoint
    return None
