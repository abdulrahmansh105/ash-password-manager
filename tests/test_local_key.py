"""Tests for core.devices.local_key -- the on-disk
``ash-pass-manager.key`` file and its identity metadata (spec sections
4, 28)."""

from __future__ import annotations

import stat

import pytest

from passman.core.devices.local_key import (
    LOCAL_KEY_FILENAME,
    LocalKeyError,
    forget_local_key,
    generate_local_key,
    has_local_key,
    load_identity,
    load_local_key,
    local_key_path,
    replace_local_key,
)


def test_generate_local_key_creates_exact_filename(isolated_xdg):
    generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    assert local_key_path("vault-1").name == LOCAL_KEY_FILENAME


def test_generate_local_key_has_owner_only_permissions(isolated_xdg):
    generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    mode = stat.S_IMODE(local_key_path("vault-1").stat().st_mode)
    assert mode == 0o600


def test_generate_local_key_is_32_random_bytes(isolated_xdg):
    secret = generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    assert len(secret.to_bytes()) == 32


def test_two_generated_keys_are_different(isolated_xdg):
    key1 = generate_local_key("vault-1", "device-1", "Device A", "file_only")
    key2 = generate_local_key("vault-2", "device-2", "Device B", "file_only")
    assert key1.to_bytes() != key2.to_bytes()


def test_generate_refuses_to_overwrite_existing_key(isolated_xdg):
    generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    with pytest.raises(LocalKeyError):
        generate_local_key("vault-1", "device-2", "Other Device", "file_only")


def test_load_local_key_round_trip(isolated_xdg):
    original = generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    loaded = load_local_key("vault-1")
    assert loaded.to_bytes() == original.to_bytes()


def test_load_local_key_missing_raises(isolated_xdg):
    with pytest.raises(LocalKeyError):
        load_local_key("no-such-vault")


def test_load_local_key_corrupt_size_raises(isolated_xdg):
    generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    local_key_path("vault-1").write_bytes(b"too-short")
    with pytest.raises(LocalKeyError):
        load_local_key("vault-1")


def test_load_identity_round_trip(isolated_xdg):
    generate_local_key("vault-1", "device-abc", "My Laptop", "secret_service")
    identity = load_identity("vault-1")
    assert identity is not None
    assert identity.device_id == "device-abc"
    assert identity.vault_id == "vault-1"
    assert identity.label == "My Laptop"
    assert identity.tier == "secret_service"


def test_load_identity_missing_returns_none(isolated_xdg):
    assert load_identity("no-such-vault") is None


def test_has_local_key(isolated_xdg):
    assert not has_local_key("vault-1")
    generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    assert has_local_key("vault-1")


def test_forget_local_key_removes_key_and_identity(isolated_xdg):
    generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    forget_local_key("vault-1")
    assert not has_local_key("vault-1")
    assert load_identity("vault-1") is None


def test_forget_local_key_on_missing_key_does_not_raise(isolated_xdg):
    forget_local_key("no-such-vault")  # must not raise


def test_replace_local_key_generates_a_different_key(isolated_xdg):
    first = generate_local_key("vault-1", "device-1", "Test Device", "file_only")
    second = replace_local_key("vault-1", "device-2", "Test Device", "file_only")
    assert first.to_bytes() != second.to_bytes()
    identity = load_identity("vault-1")
    assert identity.device_id == "device-2"
