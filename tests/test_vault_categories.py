"""Tests for the PM_Category custom field added to core/vault/kdbx.py
and core/vault/models.py -- the Manager's category sidebar (spec
section 23). Uses the real KDBX stack (skipped automatically if
pykeepass isn't installed), like tests/test_vault_kdbx.py."""

from __future__ import annotations

import pytest

pytest.importorskip("pykeepass")

from passman.core.vault.kdbx import create_vault
from passman.core.vault.models import CATEGORY_CHOICES, DEFAULT_CATEGORY, normalize_category


def test_default_category_is_logins():
    assert DEFAULT_CATEGORY == "logins"


def test_normalize_category_accepts_known_values():
    for choice in CATEGORY_CHOICES:
        assert normalize_category(choice) == choice


def test_normalize_category_rejects_unknown_and_none():
    assert normalize_category("not-a-real-category") == DEFAULT_CATEGORY
    assert normalize_category(None) == DEFAULT_CATEGORY


def test_new_account_defaults_to_logins_category(tmp_path):
    vault = create_vault(tmp_path / "v.kdbx", tmp_path / "k.key")
    uuid = vault.create_account("GitHub", "GitHub", "me", "pw")
    summary = next(s for s in vault.list_account_summaries() if s.entry_uuid == uuid)
    assert summary.category == "logins"
    vault.close()


def test_create_account_with_explicit_category_round_trips(tmp_path):
    vault = create_vault(tmp_path / "v.kdbx", tmp_path / "k.key")
    uuid = vault.create_account("Home Wi-Fi", "Wi-Fi", "", "pw", category="wifi")
    summary = next(s for s in vault.list_account_summaries() if s.entry_uuid == uuid)
    assert summary.category == "wifi"
    secrets = vault.get_account_secrets(uuid)
    assert secrets.category == "wifi"
    secrets.wipe()
    vault.close()


def test_update_account_fields_changes_category(tmp_path):
    vault = create_vault(tmp_path / "v.kdbx", tmp_path / "k.key")
    uuid = vault.create_account("Steam", "Steam", "me", "pw")
    vault.update_account_fields(uuid, category="software")
    summary = next(s for s in vault.list_account_summaries() if s.entry_uuid == uuid)
    assert summary.category == "software"
    vault.close()


def test_invalid_category_normalizes_on_write(tmp_path):
    vault = create_vault(tmp_path / "v.kdbx", tmp_path / "k.key")
    uuid = vault.create_account("Odd", "Odd", "me", "pw", category="not-a-real-one")
    summary = next(s for s in vault.list_account_summaries() if s.entry_uuid == uuid)
    assert summary.category == DEFAULT_CATEGORY
    vault.close()


def test_category_persists_across_save_and_reopen(tmp_path):
    vault_path = tmp_path / "v.kdbx"
    key_path = tmp_path / "k.key"
    vault = create_vault(vault_path, key_path)
    uuid = vault.create_account("Discord", "Discord", "me", "pw", category="software")
    vault.save()
    vault.close()

    from passman.core.vault.kdbx import open_vault

    reopened = open_vault(vault_path, key_path, password=None)
    summary = next(s for s in reopened.list_account_summaries() if s.entry_uuid == uuid)
    assert summary.category == "software"
    reopened.close()
