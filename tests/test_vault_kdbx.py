"""KDBX compatibility-layer tests -- run only against a freshly created,
throwaway vault (never a real database). Skipped automatically if
pykeepass isn't installed (``pacman -S python-pykeepass`` /
``pip install pykeepass``); see docs/USB_SETUP.md.

Every credential here is fabricated by the test itself.
"""

from __future__ import annotations

import pytest

pytest.importorskip("pykeepass")

from passman.core.auth.strategy import DEFAULT_STRATEGY
from passman.core.totp.totp import TotpConfig
from passman.core.vault.kdbx import (
    EntryNotFoundError,
    VaultOpenError,
    create_vault,
    open_vault,
)
from passman.core.vault.models import RecoveryCode

FAKE_TOTP_SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def empty_vault(tmp_path):
    vault_path = tmp_path / "Passwords.kdbx"
    key_path = tmp_path / "Key.key"
    handle = create_vault(vault_path, key_path, password=None)
    yield handle, vault_path, key_path
    handle.close()


def test_created_vault_uses_argon2id_kdf(empty_vault):
    # Required correction: pykeepass's own create_database() default is
    # Argon2d, not Argon2id. create_vault() must upgrade it, not silently
    # ship Argon2d. Verified directly against the real installed
    # pykeepass, not mocked.
    handle, vault_path, key_path = empty_vault
    handle.save()
    handle.close()

    import pykeepass

    reopened = pykeepass.PyKeePass(str(vault_path), keyfile=str(key_path))
    assert reopened.kdf_algorithm == "argon2id"


def test_create_and_reopen_empty_vault(empty_vault):
    handle, vault_path, key_path = empty_vault
    handle.save()
    handle.close()

    reopened = open_vault(vault_path, key_path, password=None)
    assert reopened.list_account_summaries() == []
    reopened.close()


def test_wrong_key_file_fails_to_open(tmp_path, empty_vault):
    handle, vault_path, _key_path = empty_vault
    handle.save()

    wrong_key = tmp_path / "wrong.key"
    create_vault(tmp_path / "throwaway.kdbx", wrong_key, password=None).close()

    with pytest.raises(VaultOpenError):
        open_vault(vault_path, wrong_key, password=None)


def test_missing_vault_file_raises(tmp_path):
    with pytest.raises(VaultOpenError):
        open_vault(tmp_path / "does-not-exist.kdbx", tmp_path / "Key.key", password=None)


def test_missing_key_file_raises(empty_vault, tmp_path):
    _handle, vault_path, _key_path = empty_vault
    with pytest.raises(VaultOpenError):
        open_vault(vault_path, tmp_path / "missing.key", password=None)


def test_corrupt_vault_file_raises(tmp_path):
    vault_path = tmp_path / "corrupt.kdbx"
    key_path = tmp_path / "Key.key"
    create_vault(vault_path, key_path, password=None).close()
    with open(vault_path, "r+b") as fh:
        fh.write(b"NOT A KDBX FILE")
    with pytest.raises(VaultOpenError):
        open_vault(vault_path, key_path, password=None)


def test_create_account_round_trips_all_fields(empty_vault):
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account(
        display_name="Demo Discord",
        service_name="Discord",
        username="demo.user#0001",
        password="Demo-Discord-Passw0rd!",
        url="https://discord.com/login",
        notes="fake demo entry",
        app_identifiers=["discord", "re:Discord"],
        auth_strategy_json=DEFAULT_STRATEGY.to_json(),
    )

    summaries = handle.list_account_summaries()
    assert len(summaries) == 1
    assert summaries[0].display_name == "Demo Discord"
    assert summaries[0].service_name == "Discord"
    assert summaries[0].has_totp is False
    assert summaries[0].has_recovery_codes is False

    secrets = handle.get_account_secrets(uuid)
    try:
        assert secrets.username == "demo.user#0001"
        assert secrets.password.to_str() == "Demo-Discord-Passw0rd!"
        assert secrets.url == "https://discord.com/login"
        assert secrets.app_identifiers == ("discord", "re:Discord")
    finally:
        secrets.wipe()


def test_account_summary_never_exposes_secrets(empty_vault):
    handle, _vp, _kp = empty_vault
    handle.create_account(
        display_name="Demo GitHub", service_name="GitHub", username="demo-user", password="hunter2-fake"
    )
    summary = handle.list_account_summaries()[0]
    summary_dump = repr(summary)
    assert "hunter2-fake" not in summary_dump
    assert "demo-user" not in summary_dump


def test_totp_round_trip(empty_vault):
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account("Demo GitHub", "GitHub", "demo-user", "fake-pw")
    handle.set_totp(uuid, TotpConfig(secret_base32=FAKE_TOTP_SECRET), issuer="GitHub")

    assert handle.list_account_summaries()[0].has_totp is True
    secrets = handle.get_account_secrets(uuid)
    try:
        assert secrets.totp is not None
        assert secrets.totp.secret_base32 == FAKE_TOTP_SECRET
    finally:
        secrets.wipe()

    handle.remove_totp(uuid)
    assert handle.list_account_summaries()[0].has_totp is False


def test_recovery_codes_round_trip(empty_vault):
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account("Demo GitHub", "GitHub", "demo-user", "fake-pw")
    codes = [RecoveryCode(code="fake-aaaa1111"), RecoveryCode(code="fake-bbbb2222", used=True)]
    handle.set_recovery_codes(uuid, codes)

    assert handle.list_account_summaries()[0].has_recovery_codes is True
    secrets = handle.get_account_secrets(uuid)
    try:
        assert len(secrets.recovery_codes) == 2
        assert secrets.recovery_codes[1].used is True
    finally:
        secrets.wipe()

    handle.remove_recovery_codes(uuid)
    assert handle.list_account_summaries()[0].has_recovery_codes is False


def test_delete_account_removes_entry(empty_vault):
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account("Demo Steam", "Steam", "demo_steam_user", "fake-pw")
    assert len(handle.list_account_summaries()) == 1
    handle.delete_account(uuid)
    assert handle.list_account_summaries() == []


def test_get_secrets_for_missing_uuid_raises(empty_vault):
    handle, _vp, _kp = empty_vault
    with pytest.raises(EntryNotFoundError):
        handle.get_account_secrets("00000000-0000-0000-0000-000000000000")


def test_update_account_fields(empty_vault):
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account("Demo Steam", "Steam", "demo_steam_user", "fake-pw")
    handle.update_account_fields(uuid, display_name="Renamed Steam", username="new-username")
    secrets = handle.get_account_secrets(uuid)
    try:
        assert secrets.display_name == "Renamed Steam"
        assert secrets.username == "new-username"
    finally:
        secrets.wipe()


def test_multiple_accounts_independent(empty_vault):
    handle, _vp, _kp = empty_vault
    handle.create_account("Demo Discord", "Discord", "u1", "p1")
    handle.create_account("Demo GitHub", "GitHub", "u2", "p2")
    handle.create_account("Demo Google", "Google", "u3", "p3")
    names = {s.display_name for s in handle.list_account_summaries()}
    assert names == {"Demo Discord", "Demo GitHub", "Demo Google"}


# -- strategy editor support: get_app_identifiers / get_auth_strategy_json,
# has_username/has_password, legacy (no strategy) and malformed strategy ---


def test_summary_reports_has_username_and_has_password(empty_vault):
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account("Demo Discord", "Discord", "demo-user", "demo-pass")
    summary = handle.list_account_summaries()[0]
    assert summary.has_username is True
    assert summary.has_password is True


def test_summary_reports_false_for_empty_username_or_password(empty_vault):
    handle, _vp, _kp = empty_vault
    handle.create_account("No Creds", "Service", "", "")
    summary = handle.list_account_summaries()[0]
    assert summary.has_username is False
    assert summary.has_password is False


def test_get_app_identifiers_never_needs_secrets(empty_vault):
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account(
        "Demo Discord", "Discord", "u", "p", app_identifiers=["discord", "re:Discord"]
    )
    assert handle.get_app_identifiers(uuid) == ("discord", "re:Discord")


def test_get_app_identifiers_empty_when_none_set(empty_vault):
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account("X", "Y", "u", "p")
    assert handle.get_app_identifiers(uuid) == ()


def test_get_auth_strategy_json_none_for_legacy_entry(empty_vault):
    # An entry created before the strategy field existed (or never
    # given one) -- get_auth_strategy_json() must return None, not raise.
    handle, _vp, _kp = empty_vault
    uuid = handle.create_account("Legacy Entry", "Service", "u", "p")
    assert handle.get_auth_strategy_json(uuid) is None


def test_legacy_entry_falls_back_to_default_strategy_via_auth_strategy_from_json(empty_vault):
    from passman.core.auth.strategy import DEFAULT_STRATEGY, AuthStrategy

    handle, _vp, _kp = empty_vault
    uuid = handle.create_account("Legacy Entry", "Service", "u", "p")
    raw = handle.get_auth_strategy_json(uuid)
    strategy = AuthStrategy.from_json(raw)
    assert strategy.steps == DEFAULT_STRATEGY.steps


def test_malformed_strategy_json_falls_back_safely_not_executed(empty_vault):
    # Simulate a corrupted/malformed PM_AuthStrategy value (e.g. from a
    # future incompatible version, or manual tampering) -- from_json()
    # must fall back to DEFAULT_STRATEGY, never raise, and never return
    # something that would make the executor run garbage.
    from passman.core.auth.strategy import DEFAULT_STRATEGY, AuthStrategy

    handle, _vp, _kp = empty_vault
    uuid = handle.create_account(
        "Malformed", "Service", "u", "p", auth_strategy_json='{"steps": [{"action": "not_a_real_action"}]}'
    )
    raw = handle.get_auth_strategy_json(uuid)
    strategy = AuthStrategy.from_json(raw)
    assert strategy.steps == DEFAULT_STRATEGY.steps


def test_strategy_with_disabled_steps_round_trips_through_real_vault(empty_vault):
    from passman.core.auth.strategy import AuthStep, AuthStrategy, StepAction

    handle, _vp, _kp = empty_vault
    strategy = AuthStrategy(
        name="custom",
        steps=(
            AuthStep(action=StepAction.TYPE_USERNAME, enabled=True),
            AuthStep(action=StepAction.KEY_TAB, enabled=False),
            AuthStep(action=StepAction.TYPE_PASSWORD, enabled=True),
        ),
    )
    uuid = handle.create_account("X", "Y", "u", "p", auth_strategy_json=strategy.to_json())
    handle.save()
    handle.close()

    reopened = open_vault(_vp, _kp, password=None)
    restored = AuthStrategy.from_json(reopened.get_auth_strategy_json(uuid))
    assert restored.steps[1].enabled is False
    reopened.close()
