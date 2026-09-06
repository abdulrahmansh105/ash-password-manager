"""User-saved custom Auto-Type strategy presets.

Presets are step *sequences* only -- structurally incapable of holding a
secret (see ``AuthStep``: no field on it ever carries typed text, only
which action to perform). Stored the same way as the rest of this
project's non-secret config: atomic write, 0700/0600 permissions,
tolerant reload of a missing/corrupt file back to "no presets" rather
than raising.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ...config.store import DIR_MODE, FILE_MODE, config_dir
from .strategy import AuthStrategy


def presets_path() -> Path:
    return config_dir() / "strategy_presets.json"


def load_custom_presets() -> dict[str, AuthStrategy]:
    path = presets_path()
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        result = {}
        for name, steps_data in raw.items():
            strategy = AuthStrategy.from_json(json.dumps({"name": name, "steps": steps_data}))
            result[name] = strategy
        return result
    except (json.JSONDecodeError, OSError, TypeError, KeyError):
        return {}


def save_custom_preset(name: str, strategy: AuthStrategy) -> None:
    """Add or overwrite one named preset. ``name`` must be non-empty;
    stored under that name regardless of ``strategy.name``."""
    if not name.strip():
        raise ValueError("Preset name must not be empty.")
    presets = load_custom_presets()
    presets[name] = strategy
    _write_all(presets)


def delete_custom_preset(name: str) -> None:
    presets = load_custom_presets()
    presets.pop(name, None)
    _write_all(presets)


def _write_all(presets: dict[str, AuthStrategy]) -> None:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, DIR_MODE)
    except OSError:
        pass
    path = presets_path()
    tmp_path = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    data = {name: [s.to_dict() for s in strategy.steps] for name, strategy in presets.items()}
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.chmod(tmp_path, FILE_MODE)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
