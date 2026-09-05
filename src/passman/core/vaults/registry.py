"""Local registry of every vault this device knows about (spec section
16: multiple independently registered vaults/USBs). This is metadata
only -- USB identity, a display name, on-USB relative paths -- never
any secret material; the actual credentials live in the key slots on
each vault's own USB (see ``core.devices.registry``).

Distinct from ``core.devices.registry``, which manages the *devices*
registered inside one vault, on its USB: this module manages the
*vaults* registered on this machine, in local config.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

from ..appdirs import config_home
from ..util.atomic_json import read_json, write_json_atomic
from .layout import DEFAULT_CONTAINER_DIRNAME, KDBX_FILENAME, KEYFILE_FILENAME

VAULTS_SCHEMA_VERSION = 1


@dataclass
class VaultRecord:
    """Duck-type compatible with ``integration.usb.identity``'s
    ``evaluate_usb_status(devices, reg)``, which only ever reads
    ``.luks_uuid``/``.filesystem_uuid`` off whatever ``reg`` is --
    keeping those two field names lets every existing USB-identity
    function (and its existing tests) keep working unchanged against
    this richer record."""

    vault_id: str
    name: str
    filesystem_uuid: str
    luks_uuid: str | None = None
    drive_serial: str | None = None
    drive_vendor: str | None = None
    drive_model: str | None = None
    container_rel_path: str = DEFAULT_CONTAINER_DIRNAME
    label: str = ""
    created_utc: str = ""
    last_seen_utc: str | None = None
    imported_from_legacy: bool = False

    @property
    def vault_rel_path(self) -> str:
        return f"{self.container_rel_path}/{KDBX_FILENAME}"

    @property
    def keyfile_rel_path(self) -> str:
        return f"{self.container_rel_path}/{KEYFILE_FILENAME}"


def _vaults_path():
    return config_home() / "vaults.json"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_vaults() -> list[VaultRecord]:
    """Deliberately does NOT seed anything from the legacy ``usb.json``
    (spec sections 5, 13, 14). An earlier version of this function did
    -- the moment it ran with no ``vaults.json`` yet, it silently
    turned a pre-rebrand legacy registration into a ready-to-use
    ``VaultRecord`` and wrote it here, which made ``vaults.json``
    non-empty *before* ``launcher.ash_daemon.run_sign_in_or_login()``
    ever got a chance to route to the Sign-in wizard. Since a legacy
    registration by definition points at a vault with no
    ``vault.json``/key slots yet (that is exactly what makes it
    legacy), the app would instead go straight to the normal Login
    window and attempt the new password-based unlock against a vault
    that was never converted -- which can never succeed, and surfaced
    as a misleading "Incorrect password" no matter what was typed.

    The correct behavior is for the Sign-in wizard's own foreign-KDBX
    detection (``core.flows.usb_setup.discover_container``) to handle
    a legacy vault exactly like any other not-yet-adopted KDBX, via
    its normal "adopt this database" offer -- which only ever runs
    when this function returns an empty list. See
    ``tests/test_vaults_registry.py::test_legacy_usb_json_is_never_silently_imported``
    for the regression test."""
    raw = read_json(_vaults_path(), None)
    if raw is None:
        return []
    records = []
    for item in raw.get("vaults", []) if isinstance(raw, dict) else []:
        try:
            records.append(VaultRecord(**{k: item[k] for k in VaultRecord.__dataclass_fields__ if k in item}))
        except (KeyError, TypeError):
            continue
    return records


def save_vaults(records: list[VaultRecord]) -> None:
    write_json_atomic(
        _vaults_path(),
        {"schema_version": VAULTS_SCHEMA_VERSION, "vaults": [asdict(r) for r in records]},
    )


def add_vault(record: VaultRecord) -> None:
    records = [r for r in load_vaults() if r.vault_id != record.vault_id]
    records.append(record)
    save_vaults(records)


def remove_vault(vault_id: str) -> None:
    save_vaults([r for r in load_vaults() if r.vault_id != vault_id])


def get_vault(vault_id: str) -> VaultRecord | None:
    for r in load_vaults():
        if r.vault_id == vault_id:
            return r
    return None


def touch_last_seen(vault_id: str) -> None:
    records = load_vaults()
    changed = False
    for r in records:
        if r.vault_id == vault_id:
            r.last_seen_utc = _now()
            changed = True
    if changed:
        save_vaults(records)
