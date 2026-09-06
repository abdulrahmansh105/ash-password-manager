"""End-to-end coverage for ``launcher.ash_daemon.run_sign_in_or_login`` --
the actual entry point behind ``ash-password-manager sign-in`` (spec
sections 1, 27, 30): given a *registered* vault, a currently-connected
matching USB must be detected and routed straight to the Login window
for that exact vault, with no other registered vault or a mismatched
USB ever taking that path.

Exercises the real ``find_connected_vault``/``find_and_mount_vault``
matching logic (only UDisks2 I/O at the bottom is faked, same idiom as
``test_usb_login_lookup.py``) all the way through ``run_sign_in_or_login``'s
own routing decision -- only the two GTK entry points it can call
(``ui.login.run_login_window`` / ``ui.locked_window.show_locked_window``)
are stubbed, so this is the real production code path for "USB
connected -> which window, for which vault" end to end, not a
reimplementation of it.
"""

from __future__ import annotations

from passman.core.vaults.registry import VaultRecord, add_vault


def _block(**overrides):
    from passman.integration.usb.udisks2 import RawBlockInfo

    defaults = {
        "object_path": "/blocks/x", "device": "/dev/sdx", "id_type": "", "id_uuid": "", "id_label": "", "id_usage": "",
        "size": 0, "read_only": False, "drive_object_path": "/drives/x", "crypto_backing_device": None,
        "mountpoints": (), "cleartext_object_path": None,
    }
    defaults.update(overrides)
    return RawBlockInfo(**defaults)


def _no_op_context(monkeypatch):
    """Never shells out to hyprctl during these tests, matching how the
    rest of the suite avoids real subprocess calls."""
    monkeypatch.setattr("passman.launcher.ash_daemon.get_active_window_context", lambda: object())
    monkeypatch.setattr("passman.launcher.ash_daemon.hypr_keybind.ensure_windows_float", lambda *a, **k: False)
    monkeypatch.setattr("passman.launcher.ash_daemon.is_ui_running", lambda: False)


def test_usb_insertion_of_registered_vault_opens_login_page_for_that_vault(monkeypatch, isolated_xdg):
    from passman.launcher import ash_daemon

    _no_op_context(monkeypatch)

    login_calls = []
    monkeypatch.setattr(
        "passman.ui.login.run_login_window",
        lambda record, mountpoint: login_calls.append((record, mountpoint)) or "FAKE_VAULT_HANDLE",
    )
    locked_calls = []
    monkeypatch.setattr(
        "passman.ui.locked_window.show_locked_window", lambda reason: locked_calls.append(reason) or 1
    )

    other = VaultRecord(vault_id="other", name="Other", filesystem_uuid="fs-other")
    target = VaultRecord(vault_id="target", name="Target", filesystem_uuid="fs-target")
    add_vault(other)
    add_vault(target)

    fs_block = _block(id_usage="filesystem", id_uuid="fs-target", mountpoints=("/media/user/TARGET",))
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))

    run_main_app_calls = []
    monkeypatch.setattr(
        "passman.launcher.ash_daemon.run_main_app",
        lambda mountpoint, record, *a, **k: run_main_app_calls.append((mountpoint, record)) or 0,
    )

    exit_code = ash_daemon.run_sign_in_or_login()

    assert locked_calls == [], "a valid connected vault must never fall through to the locked window"
    assert len(login_calls) == 1, "exactly one Login window must be shown"
    shown_record, shown_mountpoint = login_calls[0]
    assert shown_record.vault_id == "target", "must open the login page for the vault matching the connected USB, not any other registered vault"
    assert shown_mountpoint == "/media/user/TARGET"

    assert run_main_app_calls == [("/media/user/TARGET", target)], "a successful login must hand off to the main app for the same vault/mountpoint"
    assert exit_code == 0


def test_no_matching_usb_connected_shows_locked_window_not_login(monkeypatch, isolated_xdg):
    from passman.launcher import ash_daemon

    _no_op_context(monkeypatch)

    login_calls = []
    monkeypatch.setattr("passman.ui.login.run_login_window", lambda record, mountpoint: login_calls.append((record, mountpoint)) or None)
    locked_calls = []
    monkeypatch.setattr("passman.ui.locked_window.show_locked_window", lambda reason: locked_calls.append(reason) or 1)

    add_vault(VaultRecord(vault_id="v1", name="V1", filesystem_uuid="fs-1"))

    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], []))

    ash_daemon.run_sign_in_or_login()

    assert login_calls == [], "no USB connected -- the login page must never be shown"
    assert len(locked_calls) == 1


def test_unregistered_usb_identity_mismatch_does_not_open_login(monkeypatch, isolated_xdg):
    """A USB is physically connected, but its filesystem UUID does not
    match any registered vault -- must fail closed to the locked
    window, never guess or open the login page for the wrong vault."""
    from passman.launcher import ash_daemon

    _no_op_context(monkeypatch)

    login_calls = []
    monkeypatch.setattr("passman.ui.login.run_login_window", lambda record, mountpoint: login_calls.append((record, mountpoint)) or None)
    locked_calls = []
    monkeypatch.setattr("passman.ui.locked_window.show_locked_window", lambda reason: locked_calls.append(reason) or 1)

    add_vault(VaultRecord(vault_id="v1", name="V1", filesystem_uuid="fs-registered"))

    fs_block = _block(id_usage="filesystem", id_uuid="fs-unrelated-usb", mountpoints=("/media/user/OTHER",))
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))

    ash_daemon.run_sign_in_or_login()

    assert login_calls == []
    assert len(locked_calls) == 1


def test_login_cancelled_never_hands_off_to_main_app(monkeypatch, isolated_xdg):
    """If the Login window closes without unlocking (user cancelled),
    ``run_main_app`` must never be invoked for that vault."""
    from passman.launcher import ash_daemon

    _no_op_context(monkeypatch)

    monkeypatch.setattr("passman.ui.login.run_login_window", lambda record, mountpoint: None)

    add_vault(VaultRecord(vault_id="v1", name="V1", filesystem_uuid="fs-1"))
    fs_block = _block(id_usage="filesystem", id_uuid="fs-1", mountpoints=("/media/user/V1",))
    monkeypatch.setattr("passman.integration.usb.udisks2.new_client", lambda: object())
    monkeypatch.setattr("passman.integration.usb.udisks2.snapshot_from_client", lambda c: ([], [fs_block]))

    run_main_app_calls = []
    monkeypatch.setattr(
        "passman.launcher.ash_daemon.run_main_app",
        lambda *a, **k: run_main_app_calls.append((a, k)) or 0,
    )

    exit_code = ash_daemon.run_sign_in_or_login()

    assert run_main_app_calls == []
    assert exit_code == 1
