"""Coverage for ``launcher.agent.UsbWatchAgent._handle_blocks`` (spec
section 30) -- the resident background agent's half of "insert a
registered vault's USB and the sign-in UI appears automatically" with
no hotkey and no already-running window involved. ``test_usb_watch_logic.py``
already covers the pure edge-detection function this delegates to in
isolation; this exercises the actual method, including the real
``find_and_mount_vault`` matching logic (UDisks2 I/O faked, same idiom
as ``test_usb_login_lookup.py``) and the spawn/no-spawn decision it
drives.
"""

from __future__ import annotations

from passman.core.vaults.registry import VaultRecord, add_vault
from passman.launcher.agent import UsbWatchAgent, _sign_in_command


def _block(**overrides):
    from passman.integration.usb.udisks2 import RawBlockInfo

    defaults = {
        "object_path": "/blocks/x", "device": "/dev/sdx", "id_type": "", "id_uuid": "", "id_label": "", "id_usage": "",
        "size": 0, "read_only": False, "drive_object_path": "/drives/x", "crypto_backing_device": None,
        "mountpoints": (), "cleartext_object_path": None,
    }
    defaults.update(overrides)
    return RawBlockInfo(**defaults)


def _agent() -> UsbWatchAgent:
    return UsbWatchAgent.__new__(UsbWatchAgent)  # skip __init__'s Udisks2Monitor construction -- unneeded here


def test_registered_vault_usb_insertion_spawns_sign_in(monkeypatch, isolated_xdg):
    add_vault(VaultRecord(vault_id="v1", name="V1", filesystem_uuid="fs-1"))

    fs_block = _block(id_usage="filesystem", id_uuid="fs-1", mountpoints=("/media/user/V1",))
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))

    spawn_calls = []
    monkeypatch.setattr("passman.launcher.agent.subprocess.Popen", lambda cmd, **k: spawn_calls.append(cmd))

    agent = _agent()
    agent._previously_connected = set()
    agent._handle_blocks([])

    assert spawn_calls == [_sign_in_command()], "a newly-connected registered vault must spawn the sign-in UI"
    assert agent._previously_connected == {"v1"}


def test_sign_in_command_prefers_sibling_of_current_interpreter(monkeypatch, tmp_path):
    """Regression test: a systemd --user unit's PATH never includes
    ~/.local/bin (confirmed live on this machine), so resolving
    "ash-password-manager" via a bare-name PATH lookup silently failed
    to spawn the sign-in UI on every real USB insertion. The sibling
    console-script next to the current interpreter must be preferred."""
    fake_bin_dir = tmp_path / "venv" / "bin"
    fake_bin_dir.mkdir(parents=True)
    sibling = fake_bin_dir / "ash-password-manager"
    sibling.write_text("#!/bin/sh\n")
    sibling.chmod(0o755)
    monkeypatch.setattr("passman.launcher.agent.sys.executable", str(fake_bin_dir / "python"))

    assert _sign_in_command() == [str(sibling), "sign-in"]


def test_sign_in_command_falls_back_to_path_lookup_when_no_sibling(monkeypatch, tmp_path):
    monkeypatch.setattr("passman.launcher.agent.sys.executable", str(tmp_path / "nonexistent" / "python"))

    assert _sign_in_command() == ["ash-password-manager", "sign-in"]


def test_unregistered_usb_does_not_spawn_sign_in(monkeypatch, isolated_xdg):
    """A USB with no matching registered vault must never trigger the
    sign-in UI -- only a *validated* match (spec sections 1, 30)."""
    add_vault(VaultRecord(vault_id="v1", name="V1", filesystem_uuid="fs-registered"))

    fs_block = _block(id_usage="filesystem", id_uuid="fs-unrelated", mountpoints=("/media/user/OTHER",))
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))

    spawn_calls = []
    monkeypatch.setattr("passman.launcher.agent.subprocess.Popen", lambda cmd, **k: spawn_calls.append(cmd))

    agent = _agent()
    agent._previously_connected = set()
    agent._handle_blocks([])

    assert spawn_calls == []
    assert agent._previously_connected == set()


def test_already_connected_vault_does_not_respawn_on_redundant_signal(monkeypatch, isolated_xdg):
    """Edge-triggered (spec section 30): a vault still connected from
    the previous check must never spawn a second sign-in, even though
    a burst of UDisks2 signals for one physical insertion can call
    ``_handle_blocks`` more than once."""
    add_vault(VaultRecord(vault_id="v1", name="V1", filesystem_uuid="fs-1"))

    fs_block = _block(id_usage="filesystem", id_uuid="fs-1", mountpoints=("/media/user/V1",))
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))

    spawn_calls = []
    monkeypatch.setattr("passman.launcher.agent.subprocess.Popen", lambda cmd, **k: spawn_calls.append(cmd))

    agent = _agent()
    agent._previously_connected = {"v1"}  # already connected as of the last check
    agent._handle_blocks([])

    assert spawn_calls == []


def test_vault_removal_then_reinsertion_spawns_again(monkeypatch, isolated_xdg):
    add_vault(VaultRecord(vault_id="v1", name="V1", filesystem_uuid="fs-1"))
    fs_block = _block(id_usage="filesystem", id_uuid="fs-1", mountpoints=("/media/user/V1",))

    spawn_calls = []
    monkeypatch.setattr("passman.launcher.agent.subprocess.Popen", lambda cmd, **k: spawn_calls.append(cmd))

    agent = _agent()
    agent._previously_connected = set()

    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))
    agent._handle_blocks([])
    assert len(spawn_calls) == 1

    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], []))
    agent._handle_blocks([])  # removed
    assert len(spawn_calls) == 1

    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))
    agent._handle_blocks([])  # reinserted
    assert len(spawn_calls) == 2
