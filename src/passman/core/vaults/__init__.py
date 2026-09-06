"""Multi-vault registry, on-USB path layout, and vault health checks."""

from __future__ import annotations

from .health import (
    HealthCheck,
    HealthReport,
    HealthStatus,
    check_vault_health,
    update_integrity_manifest,
)
from .layout import DEFAULT_CONTAINER_DIRNAME, PathTraversalError, VaultLayout
from .registry import (
    VaultRecord,
    add_vault,
    get_vault,
    load_vaults,
    remove_vault,
    save_vaults,
    touch_last_seen,
)

__all__ = [
    "DEFAULT_CONTAINER_DIRNAME",
    "HealthCheck",
    "HealthReport",
    "HealthStatus",
    "PathTraversalError",
    "VaultLayout",
    "VaultRecord",
    "add_vault",
    "check_vault_health",
    "get_vault",
    "load_vaults",
    "remove_vault",
    "save_vaults",
    "touch_last_seen",
    "update_integrity_manifest",
]
