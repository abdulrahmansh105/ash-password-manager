"""Vault integrity manifest + health checks (spec sections 21, 24, 25).

The manifest is tamper-evident, not tamper-proof: it is plain SHA-256
hashes stored alongside the files it describes, so it cannot stop an
attacker who can rewrite arbitrary files on the USB from also
rewriting the manifest. What it reliably catches is accidental
corruption -- a failing USB, an interrupted copy, a partially-written
file -- which is exactly the "handle corrupted vaults gracefully"
requirement (spec section 25/33). Real tamper resistance for the
secret material comes from AES-GCM's own authentication tag on each
key slot (``core.crypto.aead``) and from KDBX4's own authentication;
neither of those needs this manifest.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import Enum

from ..util.atomic_json import read_json, write_json_atomic
from .layout import VaultLayout

MANIFEST_VERSION = 1


def _sha256_file(path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _tracked_files(layout: VaultLayout) -> dict[str, object]:
    files = {"vault.json": layout.vault_json, "devices.json": layout.devices_json}
    if layout.keyslots_dir.exists():
        for slot_path in sorted(layout.keyslots_dir.glob("*.slot")):
            files[f"keyslots/{slot_path.name}"] = slot_path
    return files


def update_integrity_manifest(layout: VaultLayout) -> None:
    """Recompute and persist the manifest. Called after every mutating
    write to devices.json or any key slot.

    Deliberately does NOT cover ``Passwords.kdbx`` itself -- pykeepass
    rotates that file's own seeds on every save (see
    ``pykeepass.PyKeePass.save``'s docstring), so hashing it here would
    only ever report "changed" on every legitimate save and add no
    real detection value; KDBX4 already authenticates its own
    contents independently.
    """
    entries = {name: _sha256_file(path) for name, path in _tracked_files(layout).items()}
    manifest = {
        "version": MANIFEST_VERSION,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sha256": entries,
    }
    write_json_atomic(layout.integrity_json, manifest)


class HealthStatus(str, Enum):
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class HealthCheck:
    name: str
    status: HealthStatus
    detail: str


@dataclass(frozen=True)
class HealthReport:
    checks: list[HealthCheck]

    @property
    def status(self) -> HealthStatus:
        if any(c.status is HealthStatus.ERROR for c in self.checks):
            return HealthStatus.ERROR
        if any(c.status is HealthStatus.WARNING for c in self.checks):
            return HealthStatus.WARNING
        return HealthStatus.OK


def _load_manifest(layout: VaultLayout) -> dict | None:
    return read_json(layout.integrity_json, None)


def check_vault_health(layout: VaultLayout) -> HealthReport:
    checks: list[HealthCheck] = []

    checks.append(
        HealthCheck("vault.json", HealthStatus.OK, "Present")
        if layout.vault_json.exists()
        else HealthCheck("vault.json", HealthStatus.ERROR, "Missing -- not a recognized ASH vault container")
    )
    checks.append(
        HealthCheck("Passwords.kdbx", HealthStatus.OK, "Present")
        if layout.kdbx_path.exists()
        else HealthCheck("Passwords.kdbx", HealthStatus.ERROR, "Missing")
    )
    checks.append(
        HealthCheck("Key.key", HealthStatus.OK, "Present")
        if layout.keyfile_path.exists()
        else HealthCheck("Key.key", HealthStatus.ERROR, "Missing")
    )

    password_slot = layout.keyslots_dir / "password.slot"
    checks.append(
        HealthCheck("Password slot", HealthStatus.OK, "Present")
        if password_slot.exists()
        else HealthCheck("Password slot", HealthStatus.ERROR, "Missing -- password login will fail")
    )

    device_slots = list(layout.keyslots_dir.glob("device-*.slot")) if layout.keyslots_dir.exists() else []
    checks.append(HealthCheck("Device slots", HealthStatus.OK, f"{len(device_slots)} registered device slot(s)"))

    manifest = _load_manifest(layout)
    if manifest is None:
        checks.append(HealthCheck("Integrity manifest", HealthStatus.WARNING, "No manifest recorded yet"))
    else:
        mismatches = [
            name
            for name, path in _tracked_files(layout).items()
            if manifest.get("sha256", {}).get(name) != _sha256_file(path)
        ]
        if mismatches:
            checks.append(
                HealthCheck(
                    "Integrity manifest",
                    HealthStatus.WARNING,
                    f"Changed since last recorded state: {', '.join(mismatches)}",
                )
            )
        else:
            checks.append(HealthCheck("Integrity manifest", HealthStatus.OK, "Matches on-disk files"))

    return HealthReport(checks=checks)
