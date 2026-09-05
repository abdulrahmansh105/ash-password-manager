"""Multi-vault registry, on-USB path layout, and vault health checks."""

from __future__ import annotations

from .health import HealthCheck, HealthReport, HealthStatus, check_vault_health, update_integrity_manifest
from .layout import DEFAULT_CONTAINER_DIRNAME, PathTraversalError, VaultLayout
from .registry import VaultRecord, add_vault, get_vault, load_vaults, remove_vault, save_vaults, touch_last_seen

__all__ = [
    "VaultLayout",
    "PathTraversalError",
    "DEFAULT_CONTAINER_DIRNAME",
    "HealthCheck",
    "HealthReport",
    "HealthStatus",
    "check_vault_health",
    "update_integrity_manifest",
    "VaultRecord",
    "load_vaults",
    "save_vaults",
    "add_vault",
    "remove_vault",
    "get_vault",
    "touch_last_seen",
]
