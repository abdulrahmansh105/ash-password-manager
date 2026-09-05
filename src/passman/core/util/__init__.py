"""Small, dependency-free helpers shared across ``core``."""

from __future__ import annotations

from .atomic_json import ensure_dir, read_json, write_json_atomic

__all__ = ["ensure_dir", "read_json", "write_json_atomic"]
