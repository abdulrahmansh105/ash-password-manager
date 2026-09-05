"""Tiny atomic JSON read/write helper.

The project already had this "0700 dir / 0600 file / write-temp-then-
``os.replace``" pattern hand-rolled in ``config/store.py``. Every new
module under ``core/`` that persists a small local or on-USB record
(device identity, key slots, the vault registry, the devices list)
needs the exact same pattern, so it lives here once instead of being
copy-pasted five times.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

FILE_MODE = 0o600
DIR_MODE = 0o700


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        pass


def write_json_atomic(path: Path, data: Any, *, mode: int = FILE_MODE) -> None:
    """Write ``data`` as JSON to ``path``, atomically. The directory is
    created (0700) if missing. A crash mid-write leaves either the old
    file or nothing -- never a truncated/corrupt one -- because the
    temp file is only ``os.replace``d into place after a full,
    successful write."""
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def read_json(path: Path, default: Any) -> Any:
    """Tolerant read: a missing, corrupt, or unreadable file quietly
    reverts to ``default`` rather than raising -- callers decide what
    "no valid record yet" means for their own schema."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
