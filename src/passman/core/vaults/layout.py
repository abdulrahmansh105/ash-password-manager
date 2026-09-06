"""Path layout for an ASH vault container directory on a USB (or any
mounted filesystem) -- spec section 6. A "container" is the directory
that holds one vault's ``Passwords.kdbx``; a single USB can hold
several independent containers (spec section 16: multiple vaults).

Every path this module returns is validated to stay inside the
container directory (spec section 21: protect against path traversal)
-- a corrupt or hand-edited relative path can never resolve outside
the mount.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

VAULT_FILENAME = "vault.json"
KDBX_FILENAME = "Passwords.kdbx"
KEYFILE_FILENAME = "Key.key"
KEYSLOTS_DIRNAME = "keyslots"
DEVICES_FILENAME = "devices.json"
INTEGRITY_FILENAME = "integrity.json"
ICONS_DIRNAME = "icons"
BACKUPS_DIRNAME = "backups"
DEFAULT_CONTAINER_DIRNAME = "ASH"


class PathTraversalError(Exception):
    pass


def _safe_join(base: Path, *parts: str) -> Path:
    base = base.resolve()
    candidate = base.joinpath(*parts).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise PathTraversalError(f"Refusing to resolve outside container: {parts}") from exc
    return candidate


@dataclass(frozen=True)
class VaultLayout:
    """All on-disk paths for one vault container, rooted at
    ``container_dir`` (an absolute, already-resolved path)."""

    container_dir: Path

    @staticmethod
    def at(mountpoint: str, container_rel_path: str) -> VaultLayout:
        mount = Path(mountpoint).resolve()
        container = _safe_join(mount, container_rel_path)
        return VaultLayout(container_dir=container)

    @property
    def vault_json(self) -> Path:
        return _safe_join(self.container_dir, VAULT_FILENAME)

    @property
    def kdbx_path(self) -> Path:
        return _safe_join(self.container_dir, KDBX_FILENAME)

    @property
    def keyfile_path(self) -> Path:
        return _safe_join(self.container_dir, KEYFILE_FILENAME)

    @property
    def keyslots_dir(self) -> Path:
        return _safe_join(self.container_dir, KEYSLOTS_DIRNAME)

    def keyslot_path(self, slot_id: str) -> Path:
        if not slot_id or "/" in slot_id or slot_id in {".", ".."}:
            raise PathTraversalError(f"Invalid slot id: {slot_id!r}")
        return _safe_join(self.keyslots_dir, f"{slot_id}.slot")

    @property
    def devices_json(self) -> Path:
        return _safe_join(self.container_dir, DEVICES_FILENAME)

    @property
    def integrity_json(self) -> Path:
        return _safe_join(self.container_dir, INTEGRITY_FILENAME)

    @property
    def icons_dir(self) -> Path:
        return _safe_join(self.container_dir, ICONS_DIRNAME)

    @property
    def backups_dir(self) -> Path:
        return _safe_join(self.container_dir, BACKUPS_DIRNAME)

    def exists(self) -> bool:
        return self.vault_json.exists() and self.kdbx_path.exists()

    def is_legacy_kdbx_only(self) -> bool:
        """A KDBX exists at this path but there is no ``vault.json`` --
        i.e. a non-ASH (or pre-ASH) vault. Relevant only to the
        adoption flow, which is always reached by walking a *selected,
        identified* USB, never a generic file path (spec section 14)."""
        return self.kdbx_path.exists() and not self.vault_json.exists()

    def ensure_dirs(self) -> None:
        for d in (self.container_dir, self.keyslots_dir, self.icons_dir, self.backups_dir):
            d.mkdir(parents=True, exist_ok=True)
