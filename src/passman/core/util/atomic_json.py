"""Private, durable atomic writes for local and on-USB records."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO

FILE_MODE = 0o600
DIR_MODE = 0o700


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        pass


@contextmanager
def atomic_writer(path: Path, *, mode: int = FILE_MODE) -> Iterator[BinaryIO]:
    """Publish only a fully written, fsynced file; never follow a temp symlink.

    A unique exclusive temporary file also keeps simultaneous writers from
    sharing a buffer. This does not provide application-level conflict merging.
    """
    ensure_dir(path.parent)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), mode)
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        # Directory fsync is not available on every removable filesystem.
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        tmp.unlink(missing_ok=True)


def write_json_atomic(path: Path, data: Any, *, mode: int = FILE_MODE) -> None:
    payload = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with atomic_writer(path, mode=mode) as fh:
        fh.write(payload)


def read_json(path: Path, default: Any) -> Any:
    """Tolerant configuration read; credential callers validate separately."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default
