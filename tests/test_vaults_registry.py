"""Tests for core.vaults.registry -- the local multi-vault registry
(spec sections 9, 16), and the regression test proving a legacy
usb.json is never silently imported into it (spec sections 5, 13, 14)."""

from __future__ import annotations

from passman.core.vaults.registry import VaultRecord, add_vault, get_vault, load_vaults, remove_vault, touch_last_seen


def test_no_vaults_registered_returns_empty_list(isolated_xdg):
    assert load_vaults() == []


def test_add_and_load_vault_round_trip(isolated_xdg):
    record = VaultRecord(vault_id="v1", name="My Passwords", filesystem_uuid="fs-uuid-1")
    add_vault(record)
    loaded = load_vaults()
    assert len(loaded) == 1
    assert loaded[0].vault_id == "v1"
    assert loaded[0].name == "My Passwords"
    assert loaded[0].filesystem_uuid == "fs-uuid-1"


def test_multiple_vaults_stay_independent(isolated_xdg):
    add_vault(VaultRecord(vault_id="v1", name="Personal", filesystem_uuid="fs-1"))
    add_vault(VaultRecord(vault_id="v2", name="Work", filesystem_uuid="fs-2"))
    loaded = {r.vault_id: r for r in load_vaults()}
    assert set(loaded) == {"v1", "v2"}
    assert loaded["v1"].name == "Personal"
    assert loaded["v2"].name == "Work"


def test_add_vault_replaces_existing_id_not_duplicates(isolated_xdg):
    add_vault(VaultRecord(vault_id="v1", name="Old Name", filesystem_uuid="fs-1"))
    add_vault(VaultRecord(vault_id="v1", name="New Name", filesystem_uuid="fs-1"))
    loaded = load_vaults()
    assert len(loaded) == 1
    assert loaded[0].name == "New Name"


def test_remove_vault(isolated_xdg):
    add_vault(VaultRecord(vault_id="v1", name="A", filesystem_uuid="fs-1"))
    add_vault(VaultRecord(vault_id="v2", name="B", filesystem_uuid="fs-2"))
    remove_vault("v1")
    remaining = [r.vault_id for r in load_vaults()]
    assert remaining == ["v2"]


def test_get_vault_returns_none_for_unknown_id(isolated_xdg):
    assert get_vault("nonexistent") is None


def test_touch_last_seen_updates_only_matching_record(isolated_xdg):
    add_vault(VaultRecord(vault_id="v1", name="A", filesystem_uuid="fs-1"))
    add_vault(VaultRecord(vault_id="v2", name="B", filesystem_uuid="fs-2"))
    touch_last_seen("v1")
    by_id = {r.vault_id: r for r in load_vaults()}
    assert by_id["v1"].last_seen_utc is not None
    assert by_id["v2"].last_seen_utc is None


def test_vault_record_derives_kdbx_and_keyfile_rel_paths():
    record = VaultRecord(vault_id="v1", name="A", filesystem_uuid="fs-1", container_rel_path="ASH")
    assert record.vault_rel_path == "ASH/Passwords.kdbx"
    assert record.keyfile_rel_path == "ASH/Key.key"


def test_vault_record_is_duck_type_compatible_with_usb_identity(isolated_xdg):
    """integration.usb.identity.evaluate_usb_status(devices, reg) only
    ever reads .luks_uuid/.filesystem_uuid off `reg` -- a VaultRecord
    must work as a drop-in there without any adapter."""
    from passman.integration.usb.identity import BlockDevice, evaluate_usb_status, UsbState

    record = VaultRecord(vault_id="v1", name="A", filesystem_uuid="fs-uuid-xyz", luks_uuid=None)
    devices = [BlockDevice(name="sdz", path="/dev/sdz", uuid=None, fstype=None, type="disk", mountpoint=None)]
    status = evaluate_usb_status(devices, record)
    assert status.state == UsbState.ABSENT  # no LUKS device present at all -- proves the call didn't blow up


def test_legacy_usb_json_is_never_silently_imported(isolated_xdg):
    """Regression test (spec sections 5, 13, 14). A pre-rebrand legacy
    ``usb.json`` must NEVER be silently turned into a ``VaultRecord``
    by ``load_vaults()``. It used to be: the moment this ran with no
    ``vaults.json`` yet, it fabricated a ready-to-use record from the
    legacy file and wrote it here -- which made the registry
    non-empty *before* ``launcher.ash_daemon.run_sign_in_or_login()``
    ever got a chance to route to the Sign-in wizard, so the wizard's
    "adopt this existing database" offer (core.flows.usb_setup) never
    ran. The app went straight to a Login attempt against a vault that
    was never actually converted to the new key-slot format -- which
    can never succeed, and surfaced as a misleading "Incorrect
    password" no matter what was typed.

    The fix is that ``load_vaults()`` only ever reads its own
    ``vaults.json`` -- a legacy registration is handled entirely by
    the wizard's own foreign-KDBX detection instead, exactly like any
    other not-yet-adopted vault (see test_usb_setup.py's
    ``discover_container`` tests, and test_setup_and_login_flow.py's
    end-to-end adoption test)."""
    from passman.core.appdirs import legacy_config_home
    from passman.core.util.atomic_json import write_json_atomic

    legacy_dir = legacy_config_home()
    write_json_atomic(
        legacy_dir / "usb.json",
        {
            "luks_uuid": "luks-uuid-1",
            "filesystem_uuid": "fs-uuid-1",
            "vault_rel_path": "Authentication/Passwords.kdbx",
            "keyfile_rel_path": "Authentication/Key.key",
            "label": "My USB",
        },
    )

    assert load_vaults() == []

    # The legacy file itself must never be touched -- read-only, forever.
    assert (legacy_dir / "usb.json").exists()

    # Repeated calls must stay consistently empty: no lazy, delayed,
    # or one-time-on-first-call seeding of any kind.
    assert load_vaults() == []
    assert load_vaults() == []


def test_no_legacy_file_means_no_vaults(isolated_xdg):
    assert load_vaults() == []
