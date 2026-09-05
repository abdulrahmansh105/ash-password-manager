"""Tests for core.vault.provisioning -- guarded vault creation and
adoption of a pre-existing KDBX (spec sections 3, 4, 6, 13, 14, 26).
Uses the real pykeepass/argon2-cffi/pycryptodomex stack throughout
(skipped automatically if pykeepass isn't installed), so these prove
an actually-openable vault comes out the other end, not a mock."""

from __future__ import annotations

import base64

import pytest

pykeepass = pytest.importorskip("pykeepass")

from passman.core.crypto.kdf import Argon2Params
from passman.core.devices.registry import unlock_with_local_key, unlock_with_password
from passman.core.security.memory import SecretBytes
from passman.core.vault.kdbx import generate_keyfile, open_vault
from passman.core.vault.provisioning import (
    ProvisioningError,
    VaultAlreadyExistsError,
    adopt_existing_vault,
    create_new_vault,
    read_vault_json,
)

FAST = Argon2Params(time_cost=1, memory_cost_kib=8 * 1024, parallelism=1)


def _open_kdbx_via_password_slot(layout, master_password: str):
    """Exercises the real production path end to end: master password
    -> password slot -> VMS -> base64 -> the vault's actual KDBX
    password -- not a shortcut around any of it."""
    vms = unlock_with_password(layout, SecretBytes(master_password))
    try:
        password_str = base64.urlsafe_b64encode(vms.to_bytes()).decode("ascii")
        return open_vault(layout.kdbx_path, layout.keyfile_path, SecretBytes(password_str))
    finally:
        vms.wipe()


def test_create_new_vault_produces_a_vault_that_actually_opens(fake_usb, isolated_xdg, no_secret_service):
    result = create_new_vault(
        str(fake_usb),
        "ASH",
        "My Passwords",
        SecretBytes("correct horse battery staple"),
        enroll_local_key=False,
        argon2_params=FAST,
    )
    assert result.layout.exists()
    assert result.layout.kdbx_path.exists()
    assert result.layout.keyfile_path.exists()
    assert (result.layout.keyslots_dir / "password.slot").exists()

    handle = _open_kdbx_via_password_slot(result.layout, "correct horse battery staple")
    assert handle.list_account_summaries() == []
    handle.close()


def test_create_new_vault_writes_ash_readme_at_mount_root(fake_usb, isolated_xdg, no_secret_service):
    create_new_vault(
        str(fake_usb), "ASH", "My Passwords", SecretBytes("hunter2222"), enroll_local_key=False, argon2_params=FAST
    )
    readme = fake_usb / "ASH-README.txt"
    assert readme.exists()
    assert "ASH Password Manager" in readme.read_text()


def test_create_new_vault_writes_vault_json_with_matching_id(fake_usb, isolated_xdg, no_secret_service):
    result = create_new_vault(
        str(fake_usb), "ASH", "My Passwords", SecretBytes("hunter2222"), enroll_local_key=False, argon2_params=FAST
    )
    data = read_vault_json(result.layout)
    assert data["vault_id"] == result.vault_id
    assert data["name"] == "My Passwords"


def test_create_new_vault_refuses_to_overwrite_nonempty_container(fake_usb, isolated_xdg, no_secret_service):
    container = fake_usb / "ASH"
    container.mkdir()
    (container / "some-other-file.txt").write_text("pre-existing data")

    with pytest.raises(VaultAlreadyExistsError):
        create_new_vault(
            str(fake_usb), "ASH", "My Passwords", SecretBytes("x"), enroll_local_key=False, argon2_params=FAST
        )

    assert (container / "some-other-file.txt").read_text() == "pre-existing data"
    assert not (container / "Passwords.kdbx").exists()


def test_create_new_vault_allows_an_empty_pre_existing_directory(fake_usb, isolated_xdg, no_secret_service):
    (fake_usb / "ASH").mkdir()
    result = create_new_vault(
        str(fake_usb), "ASH", "My Passwords", SecretBytes("x"), enroll_local_key=False, argon2_params=FAST
    )
    assert result.layout.exists()


def test_create_new_vault_with_local_key_enrolls_a_working_device(fake_usb, isolated_xdg, no_secret_service):
    result = create_new_vault(
        str(fake_usb),
        "ASH",
        "My Passwords",
        SecretBytes("master-pw"),
        enroll_local_key=True,
        device_label="Test Device",
        argon2_params=FAST,
    )
    assert result.device_identity is not None
    assert result.local_key is not None

    recovered = unlock_with_local_key(result.layout, result.vault_id)
    vms_via_password = unlock_with_password(result.layout, SecretBytes("master-pw"))
    assert recovered.to_bytes() == vms_via_password.to_bytes()


def test_create_new_vault_cleans_up_on_failure(fake_usb, isolated_xdg, no_secret_service, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr("passman.core.vault.provisioning.device_registry.write_devices", boom)

    with pytest.raises(ProvisioningError):
        create_new_vault(
            str(fake_usb), "ASH", "My Passwords", SecretBytes("x"), enroll_local_key=False, argon2_params=FAST
        )

    assert not (fake_usb / "ASH").exists()
    assert list(fake_usb.iterdir()) == []


def _make_legacy_kdbx(fake_usb, password, with_keyfile: bool):
    container = fake_usb / "Authentication"
    container.mkdir()
    kdbx_path = container / "Passwords.kdbx"
    keyfile_path = container / "Key.key" if with_keyfile else None
    if keyfile_path is not None:
        generate_keyfile(keyfile_path)
    kwargs = {}
    if keyfile_path is not None:
        kwargs["keyfile"] = str(keyfile_path)
    if password is not None:
        kwargs["password"] = password
    kp = pykeepass.create_database(str(kdbx_path), **kwargs)
    kp.add_entry(kp.root_group, title="Existing Account", username="user1", password="hunter2")
    kp.save()
    return container, kdbx_path, keyfile_path


def test_adopt_existing_vault_preserves_entries(fake_usb, isolated_xdg, no_secret_service):
    container, kdbx_path, keyfile_path = _make_legacy_kdbx(fake_usb, "old-pw", with_keyfile=True)

    result = adopt_existing_vault(
        str(fake_usb),
        "Authentication",
        "Adopted Vault",
        existing_password=SecretBytes("old-pw"),
        existing_keyfile_rel_path="Authentication/Key.key",
        new_master_password=SecretBytes("new-master-pw"),
        enroll_local_key=False,
        argon2_params=FAST,
    )

    assert result.layout.exists()
    assert kdbx_path.with_name(kdbx_path.name + ".pre-ash-backup").exists()

    handle = _open_kdbx_via_password_slot(result.layout, "new-master-pw")
    summaries = handle.list_account_summaries()
    assert len(summaries) == 1
    assert summaries[0].display_name == "Existing Account"
    handle.close()


def test_adopt_existing_vault_generates_keyfile_when_none_existed(fake_usb, isolated_xdg, no_secret_service):
    _make_legacy_kdbx(fake_usb, "old-pw", with_keyfile=False)

    result = adopt_existing_vault(
        str(fake_usb),
        "Authentication",
        "Adopted Vault",
        existing_password=SecretBytes("old-pw"),
        existing_keyfile_rel_path=None,
        new_master_password=SecretBytes("new-master-pw"),
        enroll_local_key=False,
        argon2_params=FAST,
    )
    assert result.layout.keyfile_path.exists()


def test_adopt_existing_vault_wrong_password_is_rolled_back(fake_usb, isolated_xdg, no_secret_service):
    container, kdbx_path, _keyfile_path = _make_legacy_kdbx(fake_usb, "old-pw", with_keyfile=True)
    original_bytes = kdbx_path.read_bytes()

    with pytest.raises(ProvisioningError):
        adopt_existing_vault(
            str(fake_usb),
            "Authentication",
            "Adopted Vault",
            existing_password=SecretBytes("WRONG-password"),
            existing_keyfile_rel_path="Authentication/Key.key",
            new_master_password=SecretBytes("new-master-pw"),
            enroll_local_key=False,
            argon2_params=FAST,
        )

    assert kdbx_path.read_bytes() == original_bytes
    assert not (container / "vault.json").exists()
    assert not kdbx_path.with_name(kdbx_path.name + ".pre-ash-backup").exists()


def test_adopt_existing_vault_refuses_when_already_ash_vault(fake_usb, isolated_xdg, no_secret_service):
    container, _kdbx_path, _keyfile_path = _make_legacy_kdbx(fake_usb, "old-pw", with_keyfile=True)
    (container / "vault.json").write_text('{"vault_id": "already-ash"}')

    with pytest.raises(ProvisioningError):
        adopt_existing_vault(
            str(fake_usb),
            "Authentication",
            "Adopted Vault",
            existing_password=SecretBytes("old-pw"),
            existing_keyfile_rel_path="Authentication/Key.key",
            new_master_password=SecretBytes("new-master-pw"),
            enroll_local_key=False,
            argon2_params=FAST,
        )


def test_adopt_existing_vault_refuses_when_no_kdbx_present(fake_usb, isolated_xdg, no_secret_service):
    (fake_usb / "Authentication").mkdir()
    with pytest.raises(ProvisioningError):
        adopt_existing_vault(
            str(fake_usb),
            "Authentication",
            "Adopted Vault",
            existing_password=SecretBytes("old-pw"),
            existing_keyfile_rel_path=None,
            new_master_password=SecretBytes("new-master-pw"),
            enroll_local_key=False,
            argon2_params=FAST,
        )
