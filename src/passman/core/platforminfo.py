"""Small, dependency-free helpers for human-readable device labels.

Deliberately NOT used for any security decision -- hostname and
``/etc/os-release`` are only ever shown to the user as a friendly
default label ("this device is called..."), fully editable at
registration time. See ``core.crypto.binding`` for the (very
different, and non-editable) values actually used for device-binding
cryptography, and its docstring for why hostname/username are
explicitly excluded from that.
"""

from __future__ import annotations

import socket
from pathlib import Path


def read_os_pretty_name() -> str:
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Linux"


def default_device_label() -> str:
    try:
        host = socket.gethostname() or "device"
    except OSError:
        host = "device"
    return f"{host} ({read_os_pretty_name()})"
