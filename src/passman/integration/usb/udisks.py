"""Subprocess wrappers around ``lsblk``/``udisksctl``. This is the only
module that shells out for USB/LUKS operations -- the app never
reimplements LUKS unlocking or filesystem mounting itself, and, critically,
never captures the LUKS passphrase: ``udisksctl unlock`` is invoked with
stdin/stdout/stderr inherited from the terminal/session so its own
prompt (or the desktop's polkit agent) handles passphrase entry directly.
This process's Python heap never holds the LUKS passphrase at all.
"""

from __future__ import annotations

import shutil
import subprocess

from .identity import BlockDevice, parse_lsblk_json


class UdisksError(Exception):
    pass


def is_available() -> bool:
    return shutil.which("udisksctl") is not None and shutil.which("lsblk") is not None


def list_block_devices() -> list[BlockDevice]:
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,PATH,UUID,FSTYPE,TYPE,MOUNTPOINT"],
            capture_output=True,
            timeout=5,
            check=True,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise UdisksError(f"lsblk failed: {type(exc).__name__}") from exc
    return parse_lsblk_json(result.stdout.decode("utf-8", errors="replace"))


def unlock(device_path: str) -> bool:
    """Invoke ``udisksctl unlock``, letting it own the passphrase prompt
    directly (no ``capture_output`` -- this process's stdio is inherited
    so the prompt/agent is real and the passphrase never passes through
    our Python code)."""
    try:
        result = subprocess.run(["udisksctl", "unlock", "-b", device_path], timeout=120, check=False)
    except (subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


def mount(mapped_device_path: str) -> str | None:
    """Mount the unlocked mapped device; returns the mountpoint on
    success. Output is captured here only to parse the mountpoint text
    udisksctl prints -- never anything secret."""
    try:
        result = subprocess.run(
            ["udisksctl", "mount", "-b", mapped_device_path],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if result.returncode != 0:
        return None
    text = result.stdout.decode("utf-8", errors="replace")
    # udisksctl prints: "Mounted /dev/mapper/xxx at /run/media/user/xxx."
    marker = " at "
    if marker in text:
        tail = text.split(marker, 1)[1].strip()
        return tail.rstrip(".").strip()
    return None


def unmount(mapped_device_path: str) -> bool:
    try:
        result = subprocess.run(
            ["udisksctl", "unmount", "-b", mapped_device_path], timeout=15, check=False
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


def lock(outer_device_path: str) -> bool:
    try:
        result = subprocess.run(["udisksctl", "lock", "-b", outer_device_path], timeout=15, check=False)
    except (subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0
