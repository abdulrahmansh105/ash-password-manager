"""UDisks2-based USB/drive enumeration and hotplug monitoring (spec
sections 2, 20, 29, 30).

Preferred over the ``lsblk``-based ``integration.usb.udisks`` module
for new code: it exposes vendor/model/serial/connection-bus directly
(``lsblk -o NAME,PATH,UUID,FSTYPE,TYPE,MOUNTPOINT`` simply has no
columns for those), and its ObjectManager signals give real hotplug
events instead of polling. ``integration.usb.udisks`` remains a fully
supported fallback, used automatically when the UDisks2
GObject-Introspection typelib isn't available -- neither module is
ever assumed to be the only path.

The actual GIR/D-Bus calls are kept to one thin adapter
(``snapshot_from_client``) that only ever extracts plain values from
live GObject properties into the small dataclasses below
(``RawDriveInfo``/``RawBlockInfo``); every real decision -- building
the ``BlockDevice`` tree, picking removable drives, formatting a
display label -- is a pure function over those plain values, so it is
fully unit-testable with synthetic fixtures and never needs a live
D-Bus/UDisks2 connection (see ``tests/test_udisks2.py``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .identity import BlockDevice

# Buses that mean "removable, plug-in media" for the USB picker (spec
# section 2: "Detect connected removable drives"). SDIO covers SD-card
# readers built into some laptops; "usb" is the overwhelmingly common
# case. Internal SATA/NVMe/etc. are deliberately excluded even when a
# drive happens to report itself as ejectable (some internal hot-swap
# bays do) -- connection-bus, not the removable/ejectable flags, is
# the reliable signal here (verified live: an internal optical drive
# reports removable=True on this project's own development machine).
REMOVABLE_BUSES = frozenset({"usb", "sdio"})


class Udisks2Error(Exception):
    pass


class Udisks2Unavailable(Udisks2Error):
    """No UDisks2 typelib, or the service is unreachable. Callers
    should fall back to ``integration.usb.udisks`` (lsblk/udisksctl)."""


@dataclass(frozen=True)
class RawDriveInfo:
    """Plain-value snapshot of one ``org.freedesktop.UDisks2.Drive``."""

    object_path: str
    vendor: str
    model: str
    serial: str
    size: int
    connection_bus: str
    removable: bool
    ejectable: bool
    optical: bool


@dataclass(frozen=True)
class RawBlockInfo:
    """Plain-value snapshot of one ``org.freedesktop.UDisks2.Block``
    (plus its Filesystem/Encrypted interfaces where present)."""

    object_path: str
    device: str
    id_type: str
    id_uuid: str
    id_label: str
    id_usage: str
    size: int
    read_only: bool
    drive_object_path: str | None
    crypto_backing_device: str | None  # UDisks2's "/" ("none") sentinel normalized to None
    mountpoints: tuple[str, ...]
    cleartext_object_path: str | None  # set only on a LUKS block that is currently unlocked


@dataclass(frozen=True)
class DriveChoice:
    """One row for the "Select your password USB" list (spec section
    2): a human label plus the object path to identify it by."""

    object_path: str
    label: str
    vendor: str
    model: str
    size: int


def format_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} TB"


def is_removable_drive(drive: RawDriveInfo) -> bool:
    return drive.connection_bus in REMOVABLE_BUSES and not drive.optical


def list_drive_choices(drives: list[RawDriveInfo]) -> list[DriveChoice]:
    """Pure: turn removable drives into display-ready rows, matching
    the exact style requested (spec section 2, e.g. "SanDisk 64GB")."""
    choices = []
    for d in drives:
        if not is_removable_drive(d):
            continue
        name_bits = [b for b in (d.vendor, d.model) if b]
        label = " ".join(name_bits) if name_bits else "Unknown USB drive"
        choices.append(
            DriveChoice(
                object_path=d.object_path,
                label=f"{label} ({format_size(d.size)})",
                vendor=d.vendor,
                model=d.model,
                size=d.size,
            )
        )
    return choices


def build_block_device_tree(blocks: list[RawBlockInfo]) -> list[BlockDevice]:
    """Convert a flat list of UDisks2 block snapshots into the exact
    nested ``BlockDevice`` shape ``integration.usb.identity`` already
    expects (a parent LUKS block with a cleartext "crypt" child once
    unlocked), so every existing identity function
    (``evaluate_usb_status``, ``should_lock_for_usb_state``,
    ``check_vault_paths``) -- and their existing tests -- work
    completely unchanged against UDisks2-sourced data."""
    cleartext_paths = {b.cleartext_object_path for b in blocks if b.cleartext_object_path}
    children_of: dict[str, RawBlockInfo] = {
        b.crypto_backing_device: b for b in blocks if b.crypto_backing_device
    }

    def to_node(b: RawBlockInfo) -> BlockDevice:
        child = children_of.get(b.object_path)
        children = (to_node(child),) if child is not None else ()
        node_type = "crypt" if b.crypto_backing_device else "disk"
        return BlockDevice(
            name=b.device.rsplit("/", 1)[-1],
            path=b.device,
            uuid=b.id_uuid or None,
            fstype=b.id_type or None,
            type=node_type,
            mountpoint=b.mountpoints[0] if b.mountpoints else None,
            children=children,
        )

    roots = [b for b in blocks if b.object_path not in cleartext_paths]
    return [to_node(b) for b in roots]


# --- live UDisks2 adapter (thin; everything above stays testable without it) ---


def _normalize_crypto_backing(raw: str | None) -> str | None:
    return None if raw in (None, "", "/") else raw


def _decode_mountpoint(raw) -> str:
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).split(b"\x00", 1)[0].decode("utf-8", "replace")
    return str(raw)


def snapshot_from_client(client) -> tuple[list[RawDriveInfo], list[RawBlockInfo]]:
    """The only function in this module that touches live GObject
    properties. Everything it returns is plain str/int/bool/tuple."""
    om = client.get_object_manager()
    drives: list[RawDriveInfo] = []
    blocks: list[RawBlockInfo] = []
    for obj in om.get_objects():
        drive = obj.get_drive()
        if drive is not None:
            drives.append(
                RawDriveInfo(
                    object_path=obj.get_object_path(),
                    vendor=(drive.get_property("vendor") or "").strip(),
                    model=(drive.get_property("model") or "").strip(),
                    serial=(drive.get_property("serial") or "").strip(),
                    size=int(drive.get_property("size") or 0),
                    connection_bus=(drive.get_property("connection-bus") or "").strip(),
                    removable=bool(drive.get_property("removable")),
                    ejectable=bool(drive.get_property("ejectable")),
                    optical=bool(drive.get_property("optical")),
                )
            )
        block = obj.get_block()
        if block is None:
            continue
        fs = obj.get_filesystem()
        mountpoints: tuple[str, ...] = ()
        if fs is not None:
            mountpoints = tuple(_decode_mountpoint(m) for m in (fs.get_property("mount-points") or []))
        encrypted = obj.get_encrypted()
        cleartext_path = None
        if encrypted is not None:
            try:
                cleartext_block = client.get_cleartext_block(block)
                if cleartext_block is not None:
                    cleartext_obj = client.get_object(cleartext_block)
                    cleartext_path = cleartext_obj.get_object_path() if cleartext_obj else None
            except Exception:  # noqa: BLE001 - best-effort; treat as "not unlocked" on any binding quirk
                cleartext_path = None
        drive_obj = client.get_drive_for_block(block)
        blocks.append(
            RawBlockInfo(
                object_path=obj.get_object_path(),
                device=block.get_property("device") or "",
                id_type=(block.get_property("id-type") or "").strip(),
                id_uuid=(block.get_property("id-uuid") or "").strip(),
                id_label=(block.get_property("id-label") or "").strip(),
                id_usage=(block.get_property("id-usage") or "").strip(),
                size=int(block.get_property("size") or 0),
                read_only=bool(block.get_property("read-only")),
                drive_object_path=drive_obj.get_object().get_object_path() if drive_obj else None,
                crypto_backing_device=_normalize_crypto_backing(block.get_property("crypto-backing-device")),
                mountpoints=mountpoints,
                cleartext_object_path=cleartext_path,
            )
        )
    return drives, blocks


def new_client():
    try:
        import gi

        gi.require_version("UDisks", "2.0")
        from gi.repository import UDisks
    except (ImportError, ValueError) as exc:
        raise Udisks2Unavailable("UDisks2 GObject-Introspection typelib is not available.") from exc
    try:
        return UDisks.Client.new_sync(None)
    except Exception as exc:
        raise Udisks2Unavailable(f"Could not connect to UDisks2: {type(exc).__name__}") from exc


def is_available() -> bool:
    try:
        new_client()
        return True
    except Udisks2Unavailable:
        return False


def list_removable_drive_choices() -> list[DriveChoice]:
    client = new_client()
    drives, _blocks = snapshot_from_client(client)
    return list_drive_choices(drives)


def list_block_devices() -> list[BlockDevice]:
    """Drop-in replacement for
    ``integration.usb.udisks.list_block_devices()`` -- returns the
    identical ``BlockDevice`` tree shape, sourced from UDisks2 instead
    of an ``lsblk`` subprocess."""
    client = new_client()
    _drives, blocks = snapshot_from_client(client)
    return build_block_device_tree(blocks)


class Udisks2Monitor:
    """Watches UDisks2's ObjectManager for added/removed block devices
    and re-evaluates on every change (spec section 30: "monitor
    removable media events"). Requires a running GLib main loop to
    actually dispatch the D-Bus signals -- normal for a GTK
    application, and exactly why this lives alongside the GIR adapter
    rather than in ``core/``.

    Deliberately re-enumerates the whole device world on each signal
    rather than diffing individual objects -- the callback receives
    the current ``BlockDevice`` tree, and the caller's own
    identity-matching logic (``core.vaults.registry`` +
    ``integration.usb.identity``, already exhaustively tested)
    decides what actually changed. This also means a burst of
    add/remove signals from one physical insertion collapses into
    however many callback calls happen, never more than that -- it
    does not, by itself, cause duplicate login popups (see spec
    section 30 and ``ui/login``'s own single-flight guard for the
    other half of that guarantee).
    """

    def __init__(self, on_change: Callable[[list[BlockDevice]], None]) -> None:
        self._on_change = on_change
        self._client = None
        self._signal_ids: list[int] = []

    def start(self) -> bool:
        try:
            self._client = new_client()
        except Udisks2Unavailable:
            return False
        om = self._client.get_object_manager()
        self._signal_ids = [
            om.connect("object-added", self._handle_change),
            om.connect("object-removed", self._handle_change),
        ]
        return True

    def _handle_change(self, *_args) -> None:
        try:
            _drives, blocks = snapshot_from_client(self._client)
            self._on_change(build_block_device_tree(blocks))
        except Exception:  # noqa: BLE001 - a monitor callback must never crash the app
            pass

    def stop(self) -> None:
        if self._client is not None:
            om = self._client.get_object_manager()
            for sig_id in self._signal_ids:
                try:
                    om.disconnect(sig_id)
                except Exception:  # noqa: BLE001
                    pass
        self._signal_ids = []
        self._client = None
