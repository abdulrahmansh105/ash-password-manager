"""Vault provisioning: guarded creation, adoption of a pre-existing
KDBX, and the high-level "new vault + first device" flow (spec
sections 3, 4, 6, 13, 14, 26).

This is the module the setup wizard actually calls. It composes:

  core.vault.kdbx        -- the KDBX4 file itself (existing, unmodified
                             except for the small additive ``rekey()``
                             method added for the adoption path)
  core.crypto.keyslots   -- VMS + password/device key slots
  core.devices.registry  -- devices.json + slot file I/O
  core.vaults.layout     -- traversal-safe on-USB paths
  core.vaults.health     -- integrity manifest

``create_new_vault`` refuses a non-empty destination and publishes a fully
initialized vault from a private sibling directory. Adoption keeps a
``.pre-ash-backup`` of the original encrypted database and rolls back on
caught errors. If the process is interrupted during adoption, that backup
and the original credentials remain available for manual recovery.

"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import uuid as uuid_mod
from dataclasses import dataclass
from pathlib import Path

from ..crypto import keyslots
from ..crypto.keyslots import Argon2Params
from ..devices import local_key
from ..devices import registry as device_registry
from ..devices.local_key import DeviceIdentity
from ..platforminfo import default_device_label, read_os_pretty_name
from ..security.memory import SecretBytes
from ..util.atomic_json import atomic_writer, read_json, write_json_atomic
from ..vaults import health
from ..vaults.layout import VaultLayout
from .kdbx import VaultOpenError, generate_keyfile, open_vault
from .kdbx import create_vault as _create_kdbx

VAULT_SCHEMA_VERSION = 1


class ProvisioningError(Exception):
    pass


class VaultAlreadyExistsError(ProvisioningError):
    """Refuses to silently overwrite an existing vault container."""


def _new_vault_id() -> str:
    return uuid_mod.uuid4().hex


def _write_vault_json(layout: VaultLayout, vault_id: str, name: str) -> None:
    write_json_atomic(
        layout.vault_json,
        {
            "schema_version": VAULT_SCHEMA_VERSION,
            "vault_id": vault_id,
            "name": name,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "app": "ash-password-manager",
        },
    )


def read_vault_json(layout: VaultLayout) -> dict | None:
    return read_json(layout.vault_json, None)


@dataclass(frozen=True)
class ProvisionResult:
    vault_id: str
    layout: VaultLayout
    device_identity: DeviceIdentity | None
    local_key: SecretBytes | None


def _bootstrap_password_slot_and_devices(
    layout: VaultLayout,
    vault_id: str,
    vms: SecretBytes,
    master_password: SecretBytes,
    argon2_params: Argon2Params | None,
) -> None:
    password_slot = keyslots.create_password_slot(
        vault_id,
        keyslots.PASSWORD_SLOT_ID,
        master_password,
        vms,
        params=argon2_params,
    )
    device_registry.write_slot(layout, password_slot)
    device_registry.write_devices(layout, [])


_ASH_README_TEXT = """This USB contains an ASH Password Manager vault.

What this is
------------
A vault created by ASH Password Manager: a USB-first, device-bound
password manager for Linux. Your entries are encrypted (KDBX4); the
key material that unlocks them lives partly here (as "key slots") and
partly on each device you have registered.

To open it
----------
Install ASH Password Manager (if it isn't already) and connect this
USB:

    pipx install ash-password-manager
    ash-password-manager sign-in

This does NOT run anything automatically -- nothing on this USB is
ever executed just because it was plugged in. If a consent-based
install helper is present in the install/ directory next to this
file, you may run it yourself; it will ask for confirmation before
doing anything and installs for your user only (no root) unless you
explicitly choose otherwise.

This USB carries no password, no device key, and no machine
fingerprint by itself -- see this project's docs/SECURITY.md for
exactly what protects your data and what does not.
"""


def _write_ash_readme(mountpoint: str) -> None:
    """Best-effort, idempotent: written once per USB (not per vault
    container), never overwritten if already present so a user's own
    edits or a differently-worded version from an older release are
    left alone. Failure here must never fail vault creation itself."""
    try:
        readme_path = Path(mountpoint) / "ASH-README.txt"
        if not readme_path.exists():
            readme_path.write_text(_ASH_README_TEXT, encoding="utf-8")
    except OSError:
        pass


def create_new_vault(
    mountpoint: str,
    container_rel_path: str,
    name: str,
    master_password: SecretBytes,
    *,
    enroll_local_key: bool,
    device_label: str | None = None,
    argon2_params: Argon2Params | None = None,
) -> ProvisionResult:
    """The whole VAULT_CREATION + DEVICE_REGISTRATION setup-flow step
    (spec section 26), as one all-or-nothing operation."""
    layout = VaultLayout.at(mountpoint, container_rel_path)
    if layout.container_dir.exists() and any(layout.container_dir.iterdir()):
        raise VaultAlreadyExistsError(f"A vault or file already exists at {layout.container_dir}")

    vault_id = _new_vault_id()
    layout.container_dir.parent.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix=f".{layout.container_dir.name}.setup-", dir=layout.container_dir.parent))
    work_layout = VaultLayout(container_dir=work_dir)

    identity: DeviceIdentity | None = None
    local_secret: SecretBytes | None = None
    try:
        work_layout.ensure_dirs()
        _write_vault_json(work_layout, vault_id, name)

        vms = keyslots.generate_vms()
        try:
            handle = _create_kdbx(
                work_layout.kdbx_path, work_layout.keyfile_path, password=SecretBytes(keyslots.vms_to_kdbx_password(vms))
            )
            handle.close()

            _bootstrap_password_slot_and_devices(work_layout, vault_id, vms, master_password, argon2_params)

            if enroll_local_key:
                label = device_label or default_device_label()
                identity, local_secret = device_registry.register_device(
                    work_layout, vault_id, vms, label, os_release=read_os_pretty_name()
                )
        finally:
            vms.wipe()

        health.update_integrity_manifest(work_layout)
        layout.container_dir.parent.mkdir(parents=True, exist_ok=True)
        os.replace(work_layout.container_dir, layout.container_dir)
    except Exception as exc:
        shutil.rmtree(work_layout.container_dir, ignore_errors=True)
        if enroll_local_key:
            local_key.forget_local_key(vault_id)
        raise ProvisioningError(
            f"Vault creation failed ({type(exc).__name__}); no partial vault was left behind."
        ) from exc

    _write_ash_readme(mountpoint)
    return ProvisionResult(vault_id=vault_id, layout=layout, device_identity=identity, local_key=local_secret)


def adopt_existing_vault(
    mountpoint: str,
    container_rel_path: str,
    name: str,
    *,
    existing_password: SecretBytes | None,
    existing_keyfile_rel_path: str | None,
    new_master_password: SecretBytes,
    enroll_local_key: bool,
    device_label: str | None = None,
    argon2_params: Argon2Params | None = None,
) -> ProvisionResult:
    """Adopt a pre-existing KDBX (KeePass- or KeePassXC-created, or
    from a prior version of this project) found in a container that
    has no ``vault.json`` yet, into the ASH key-slot model.

    Scoped deliberately: the caller must already have located this
    container by walking a *selected, identified* USB (see
    ``core.flows.setup_machine``) -- this function never accepts an
    arbitrary filesystem path from a generic file picker (spec section
    14 bans exactly that kind of generic import).

    The original KDBX is copied to ``Passwords.kdbx.pre-ash-backup``
    before anything else, and restored on any failure, so an
    interrupted or failed adoption can never destroy the only copy of
    the user's existing data.
    """
    layout = VaultLayout.at(mountpoint, container_rel_path)
    if not layout.kdbx_path.exists():
        raise ProvisioningError(f"No KDBX file found at {layout.kdbx_path}")
    if layout.vault_json.exists():
        raise ProvisioningError("This container is already an ASH vault; use create_new_vault for a new one.")
    if any(layout.keyslots_dir.glob("*.slot")):
        raise ProvisioningError("Existing key slots were found. Preserve them and recover the original ASH vault before adoption.")

    existing_keyfile_path = None
    if existing_keyfile_rel_path:
        mount = Path(mountpoint).resolve()
        existing_keyfile_path = (mount / existing_keyfile_rel_path).resolve()
        if not existing_keyfile_path.is_relative_to(mount):
            raise ProvisioningError("The existing key file must be on the selected USB.")
        if existing_keyfile_path != layout.keyfile_path and layout.keyfile_path.exists():
            raise ProvisioningError("The destination Key.key already exists; refusing to overwrite it.")

    if existing_keyfile_path is None and layout.keyfile_path.exists():
        raise ProvisioningError("Key.key already exists. Select the matching existing key file or preserve it before adoption.")

    backup_path = layout.kdbx_path.with_name(layout.kdbx_path.name + ".pre-ash-backup")
    if backup_path.exists():
        raise ProvisioningError(f"A backup already exists at {backup_path}; refusing to overwrite it.")
    # Copy first (harmless either way), then open for real -- there is
    # no separate "validate, then reopen" step: open_vault() wipes its
    # password argument as soon as it returns (success or failure), so
    # a genuine second open would need a second copy of the password
    # anyway. A single successful open *is* the validation.
    shutil.copy2(layout.kdbx_path, backup_path)
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass

    try:
        handle = open_vault(layout.kdbx_path, existing_keyfile_path, existing_password)
    except VaultOpenError as exc:
        try:
            backup_path.unlink()
        except FileNotFoundError:
            pass
        raise ProvisioningError(f"Could not open the existing vault with the credentials provided: {exc}") from exc

    vault_id = _new_vault_id()
    identity: DeviceIdentity | None = None
    local_secret: SecretBytes | None = None
    generated_keyfile = existing_keyfile_path is None or existing_keyfile_path != layout.keyfile_path
    handle_closed = False
    metadata_before = {path: path.read_bytes() if path.exists() else None
                       for path in (layout.vault_json, layout.devices_json, layout.integrity_json)}
    slots_before = set(layout.keyslots_dir.glob("*.slot"))
    try:
        vms = keyslots.generate_vms()
        try:
            if existing_keyfile_path is None:
                generate_keyfile(layout.keyfile_path)
            elif generated_keyfile:
                fd = os.open(layout.keyfile_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as target, existing_keyfile_path.open("rb") as source:
                    shutil.copyfileobj(source, target)
                    target.flush()
                    os.fsync(target.fileno())
            handle.rekey(password=keyslots.vms_to_kdbx_password(vms), keyfile=str(layout.keyfile_path))
            handle.save()
            handle.close()
            handle_closed = True

            _write_vault_json(layout, vault_id, name)
            _bootstrap_password_slot_and_devices(layout, vault_id, vms, new_master_password, argon2_params)

            if enroll_local_key:
                label = device_label or default_device_label()
                identity, local_secret = device_registry.register_device(
                    layout, vault_id, vms, label, os_release=read_os_pretty_name()
                )
        finally:
            vms.wipe()
    except Exception as exc:
        if not handle_closed:
            handle.close()
        shutil.copy2(backup_path, layout.kdbx_path)
        # Preserve pre-existing unrelated metadata; remove only slots made
        # by this attempt. Never delete all contents of a legacy directory.
        for path, contents in metadata_before.items():
            if contents is None:
                path.unlink(missing_ok=True)
            else:
                with atomic_writer(path) as fh:
                    fh.write(contents)
        for path in set(layout.keyslots_dir.glob("*.slot")) - slots_before:
            path.unlink(missing_ok=True)
        if generated_keyfile:
            try:
                layout.keyfile_path.unlink()
            except FileNotFoundError:
                pass
        if enroll_local_key:
            local_key.forget_local_key(vault_id)
        raise ProvisioningError(f"Adoption failed and was rolled back ({type(exc).__name__}).") from exc

    health.update_integrity_manifest(layout)
    _write_ash_readme(mountpoint)
    return ProvisionResult(vault_id=vault_id, layout=layout, device_identity=identity, local_key=local_secret)
