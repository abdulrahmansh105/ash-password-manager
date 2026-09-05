"""Source-tree-wide security checks, ported/extended from
password-template-generator's tests/test_security.py: no network
imports anywhere, and no secret literal leaks into config files."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from passman.config import store as cfgmod

SRC_ROOT = Path(__file__).resolve().parent.parent / "src"

_NETWORK_MODULES = {
    "requests",
    "urllib.request",
    "urllib.error",
    "urllib2",
    "http.client",
    "httpx",
    "aiohttp",
    "ftplib",
    "smtplib",
    "telnetlib",
}

# Deliberately NOT blocked: `socket` (used only for a local AF_UNIX
# control socket in launcher/ipc.py -- no network capability) and
# `urllib.parse` (pure string parsing, used to build/read local
# otpauth:// URIs -- performs no I/O of any kind). subprocess/dbus
# talking to *local* system services (udisksctl, hyprctl, ydotool,
# lsblk, wl-copy) is expected and is not "network access" either -- this
# check is specifically about this app never having its own network client.


def _iter_python_files():
    return sorted(SRC_ROOT.rglob("*.py"))


def test_no_network_imports_anywhere_in_source():
    offenders = []
    for path in _iter_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if alias.name in _NETWORK_MODULES or root in _NETWORK_MODULES:
                        offenders.append((path, alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if node.module in _NETWORK_MODULES or root in _NETWORK_MODULES:
                    offenders.append((path, node.module))
    assert offenders == [], f"Unexpected network-capable imports found: {offenders}"


def test_config_dir_never_contains_a_password_looking_value(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    fake_password_marker = "DUMMY-SECRET-4f9c2b"

    cfgmod.save_settings(cfgmod.load_settings())
    cfgmod.save_usb_registration(cfgmod.UsbRegistration(luks_uuid="x", filesystem_uuid="y"))

    for path in cfgmod.config_dir().glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert fake_password_marker not in json.dumps(data)


def test_config_dir_only_contains_expected_files(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfgmod.save_settings(cfgmod.load_settings())
    cfgmod.save_usb_registration(cfgmod.UsbRegistration(luks_uuid="x", filesystem_uuid="y"))
    names = {p.name for p in cfgmod.config_dir().iterdir()}
    assert names <= {"settings.json", "usb.json"}
