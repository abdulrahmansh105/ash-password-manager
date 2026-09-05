"""USB identity model and verification -- pure logic, no subprocess
calls (those live in ``integration.usb.udisks``), so this is fully unit
testable with synthetic ``lsblk -J`` output.

Spec section 4/27: identity is a stable device/filesystem identifier +
expected vault/key-file relative paths, never a filesystem label or a
mount path (mount paths change; labels are attacker/user-editable).

Supports two shapes of registration, both driven entirely by whether
``luks_uuid`` is set (falsy = plain filesystem -- mirrors
``core.flows.usb_login_lookup.find_and_mount_vault``'s own, already-
correct branch for exactly this, which this module did not originally
match):

* **LUKS-backed** (the original single-vault design's only supported
  shape, and this project's own real vault): identity is the *outer*
  LUKS UUID plus the *inner*, post-unlock filesystem UUID -- two
  independent checks, so a coincidentally-matching LUKS UUID with a
  different (or re-formatted) inner filesystem is never trusted
  (``UsbState.IDENTITY_MISMATCH``).
* **Plain filesystem** (an ordinary, unencrypted USB stick -- what the
  new multi-vault Sign-in wizard actually creates by default when the
  selected drive has no LUKS layer at all): identity is that
  filesystem's own UUID directly. There is no "outer/inner" split to
  mismatch, so there is no analogous IDENTITY_MISMATCH state for this
  shape -- the device with that UUID either exists or it doesn't.

Before this module supported the plain-filesystem shape, any
``VaultRecord`` with ``luks_uuid=None`` -- the normal, default case for
a vault created on an ordinary USB stick -- was unconditionally
reported ``ABSENT`` here even while genuinely connected and mounted,
which under the "lock on USB removal" default would self-lock such a
vault within one poll tick of every successful unlock. Confirmed live
and fixed; see ``tests/test_usb_identity.py``'s plain-filesystem cases.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ...config.store import UsbRegistration


@dataclass(frozen=True)
class BlockDevice:
    name: str
    path: str
    uuid: str | None
    fstype: str | None
    type: str
    mountpoint: str | None
    children: tuple["BlockDevice", ...] = field(default_factory=tuple)

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()


def parse_lsblk_json(raw: str) -> list[BlockDevice]:
    data = json.loads(raw)
    return [_parse_device(d) for d in data.get("blockdevices", [])]


def _parse_device(d: dict) -> BlockDevice:
    children = tuple(_parse_device(c) for c in d.get("children", []) or [])
    return BlockDevice(
        name=d.get("name", ""),
        path=d.get("path") or f"/dev/{d.get('name', '')}",
        uuid=d.get("uuid"),
        fstype=d.get("fstype"),
        type=d.get("type", ""),
        mountpoint=d.get("mountpoint"),
        children=children,
    )


def find_luks_device(devices: list[BlockDevice], luks_uuid: str) -> BlockDevice | None:
    for root in devices:
        for dev in root.walk():
            if dev.fstype == "crypto_LUKS" and dev.uuid == luks_uuid:
                return dev
    return None


def find_unlocked_child(luks_device: BlockDevice, filesystem_uuid: str) -> BlockDevice | None:
    for child in luks_device.children:
        if child.type == "crypt" and child.uuid == filesystem_uuid:
            return child
    return None


def find_filesystem_device(devices: list[BlockDevice], filesystem_uuid: str) -> BlockDevice | None:
    """Locates a plain (non-LUKS) filesystem device by its own
    filesystem UUID directly -- mirrors
    ``core.flows.usb_login_lookup.find_and_mount_vault``'s existing,
    already-correct non-LUKS branch. Excludes ``crypto_LUKS`` devices
    themselves (whose reported ``uuid`` is the *outer* LUKS UUID, not
    an inner filesystem's) so a coincidental match there is never
    trusted -- consistent with this module's existing "never trust a
    coincidental identity match" rule for the LUKS path."""
    for root in devices:
        for dev in root.walk():
            if dev.fstype == "crypto_LUKS":
                continue
            if dev.uuid == filesystem_uuid:
                return dev
    return None


class UsbState(Enum):
    ABSENT = "absent"  # registered identifier not present on any device
    LOCKED = "locked"  # LUKS-only: present, not yet unlocked (no crypt child)
    UNLOCKED_NOT_MOUNTED = "unlocked_not_mounted"  # LUKS-only: unlocked, not mounted
    PRESENT_NOT_MOUNTED = "present_not_mounted"  # plain filesystem: found, not mounted
    MOUNTED = "mounted"
    IDENTITY_MISMATCH = "identity_mismatch"  # LUKS-only: unlocked child's fs UUID
    # doesn't match the registration -- e.g. wrong LUKS UUID coincidence,
    # or someone re-formatted the inner filesystem. Never trusted. A
    # plain filesystem has no outer/inner split to mismatch, so it has
    # no equivalent of this state -- it is simply ABSENT or found.


@dataclass(frozen=True)
class UsbStatus:
    state: UsbState
    mountpoint: str | None = None
    mapped_device_path: str | None = None
    outer_device_path: str | None = None


def should_lock_for_usb_state(status: UsbStatus, expected_mountpoint: str) -> bool:
    """Pure decision function for the "USB removal must trigger
    immediate lock" requirement -- deliberately separated from any
    polling/timer/GLib code so it is fully unit-testable with synthetic
    ``UsbStatus`` values (mocked device events) before ever touching
    real hardware. True means "lock now": the device is gone, still
    locked, mounted somewhere unexpected, or its identity no longer
    matches (fail-closed on anything other than an exact, verified
    match to the mountpoint the vault was actually opened from)."""
    if status.state != UsbState.MOUNTED:
        return True
    if status.mountpoint != expected_mountpoint:
        return True
    return False


def should_lock_for_usb_removal(status: UsbStatus, expected_mountpoint: str, usb_removal_action: str) -> bool:
    """Combines the pure security-boundary signal above with the
    user's configured USB-removal policy (spec section 10's "Lock
    immediately" vs "Keep unlocked" choice). Kept as a separate
    function -- rather than adding a parameter to
    ``should_lock_for_usb_state`` -- so that function's own semantics,
    and every existing caller/test of it, are completely unaffected;
    this one is the only thing ``ui.app.PasswordManagerApp`` should
    call for the removal-triggered lock decision.

    ``usb_removal_action == "keep_unlocked"`` means a detected removal
    must never, by itself, trigger a lock -- so this always returns
    False for that policy, regardless of the underlying USB state.
    Any other value (including the default, "lock_immediately")
    preserves the original fail-closed behavior exactly."""
    if usb_removal_action == "keep_unlocked":
        return False
    return should_lock_for_usb_state(status, expected_mountpoint)


def evaluate_usb_status(devices: list[BlockDevice], reg: UsbRegistration) -> UsbStatus:
    """``reg`` is duck-typed (the legacy ``UsbRegistration`` or a
    ``core.vaults.registry.VaultRecord``) -- only ``.luks_uuid``/
    ``.filesystem_uuid`` are ever read off it. A falsy ``luks_uuid``
    (``None`` or ``""`` -- the normal shape for a vault created on an
    ordinary, unencrypted USB stick) selects the plain-filesystem path
    below instead of the LUKS path; every legacy caller's registration
    always has a real LUKS UUID (spec section 34: ``password-manager
    setup`` only ever registers a ``crypto_LUKS`` device), so this is
    purely additive for them."""
    if not reg.luks_uuid:
        return _evaluate_plain_filesystem_status(devices, reg.filesystem_uuid)

    outer = find_luks_device(devices, reg.luks_uuid)
    if outer is None:
        return UsbStatus(state=UsbState.ABSENT)

    unlocked = find_unlocked_child(outer, reg.filesystem_uuid)
    if unlocked is None:
        # Either not unlocked at all, or unlocked but with a mismatched
        # inner filesystem -- distinguish so callers never trust a
        # coincidental/attacker-crafted volume with a matching LUKS UUID
        # but a different (or re-created) inner filesystem.
        if outer.children:
            return UsbStatus(state=UsbState.IDENTITY_MISMATCH, outer_device_path=outer.path)
        return UsbStatus(state=UsbState.LOCKED, outer_device_path=outer.path)

    if unlocked.mountpoint:
        return UsbStatus(
            state=UsbState.MOUNTED,
            mountpoint=unlocked.mountpoint,
            mapped_device_path=unlocked.path,
            outer_device_path=outer.path,
        )
    return UsbStatus(
        state=UsbState.UNLOCKED_NOT_MOUNTED,
        mapped_device_path=unlocked.path,
        outer_device_path=outer.path,
    )


def _evaluate_plain_filesystem_status(devices: list[BlockDevice], filesystem_uuid: str) -> UsbStatus:
    """The non-LUKS counterpart to the LUKS branch above: one
    identifier, no outer/inner split, so no locked/unlocked or
    identity-mismatch distinction applies -- just absent, present, or
    present-and-mounted."""
    target = find_filesystem_device(devices, filesystem_uuid)
    if target is None:
        return UsbStatus(state=UsbState.ABSENT)
    if target.mountpoint:
        return UsbStatus(state=UsbState.MOUNTED, mountpoint=target.mountpoint, mapped_device_path=target.path)
    return UsbStatus(state=UsbState.PRESENT_NOT_MOUNTED, mapped_device_path=target.path)


@dataclass(frozen=True)
class VaultPathStatus:
    """Existence-only check (never reads file contents) of the
    registered vault/key-file *relative* paths under a mounted USB.
    Spec requirement: never assume the vault sits at the filesystem
    root -- ``UsbRegistration.vault_rel_path``/``keyfile_rel_path`` can
    be any relative path (e.g. ``Authentication/Passwords.kdbx``), and
    this is the only place that resolves them against a mountpoint."""

    vault_exists: bool
    keyfile_exists: bool


def check_vault_paths(mountpoint: str, reg: UsbRegistration) -> VaultPathStatus:
    """Resolve ``reg``'s relative paths against ``mountpoint`` (the
    *verified* mounted USB root from ``evaluate_usb_status`` -- never a
    guessed or hardcoded path) and check existence only. No file is
    opened or read; this can never expose vault/key-file contents."""
    base = Path(mountpoint)
    return VaultPathStatus(
        vault_exists=(base / reg.vault_rel_path).exists(),
        keyfile_exists=(base / reg.keyfile_rel_path).exists(),
    )
