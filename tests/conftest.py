"""Shared fixtures for the credential/device/vault test layers.

Existing tests intentionally keep their own inline
``monkeypatch.setenv(...)`` style; this file adds fixtures only for
the newer modules that need a fully isolated XDG environment (config,
data, state, and runtime dirs all redirected under ``tmp_path``) plus
a fake USB mountpoint, so each test gets a clean filesystem sandbox
with no risk of touching the real user environment or a real device.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def isolated_xdg(tmp_path, monkeypatch):
    """Redirect every XDG base directory this project reads into an
    isolated tmp_path subtree."""
    config = tmp_path / "xdg-config"
    data = tmp_path / "xdg-data"
    state = tmp_path / "xdg-state"
    runtime = tmp_path / "xdg-runtime"
    for d in (config, data, state, runtime):
        d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    return {"config": config, "data": data, "state": state, "runtime": runtime}


@pytest.fixture
def fake_usb(tmp_path):
    """A plain directory standing in for a mounted USB filesystem --
    good enough for every test that only needs a real filesystem to
    read/write vault files against, with no real removable media or
    UDisks2 involved."""
    mount = tmp_path / "fake-usb"
    mount.mkdir(parents=True, exist_ok=True)
    return mount


@pytest.fixture
def no_secret_service(monkeypatch):
    """Force every core.devices.secret_store call onto the FILE_ONLY
    path, deterministically -- this is also this project's own
    development machine's real state (libsecret GI typelib present,
    no Secret Service daemon activatable), so it is the
    default-exercised tier rather than an exotic edge case."""
    monkeypatch.setattr("passman.core.devices.secret_store._try_import_secret", lambda: None)
