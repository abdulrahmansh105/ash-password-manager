"""Explicit, targeted proofs for the required no-secret-persistence
guarantees (spec section 11/31/32/34):

- passwords never enter logs
- TOTP codes/secrets never enter logs
- recovery codes never enter logs
- credentials never appear in subprocess argv
- credentials are never written to temporary plaintext files

Every value here is fabricated by the test itself.
"""

from __future__ import annotations

import inspect
import logging

import pytest

from passman.core.auth.detection import DetectedContext
from passman.core.auth.engine import LoginEngine, SafetyGuardMode
from passman.core.auth.strategy import DEFAULT_STRATEGY
from passman.core.security.memory import SecretBytes
from passman.core.totp.totp import TotpConfig, generate_totp
from passman.core.vault.models import AccountSecrets
from passman.input.backend import AuthInputBackend, BackendOutcome, InputResult
from passman.integration.usb import udisks

FAKE_PASSWORD = "fake-super-secret-Pa55w0rd!"
FAKE_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
FAKE_RECOVERY_CODE = "fake-recovery-9f8e7d6c"


class RecordingBackend(AuthInputBackend):
    name = "recording"

    def is_available(self) -> bool:
        return True

    def type_text(self, secret: bytes) -> BackendOutcome:
        return BackendOutcome(InputResult.OK)

    def press_key(self, key: str) -> BackendOutcome:
        return BackendOutcome(InputResult.OK)

    def press_combo(self, combo: str) -> BackendOutcome:
        return BackendOutcome(InputResult.OK)


def _fake_account() -> AccountSecrets:
    return AccountSecrets(
        entry_uuid="fake-uuid",
        display_name="Demo Discord",
        service_name="Discord",
        username="demo.user",
        password=SecretBytes(FAKE_PASSWORD),
        url="https://discord.com",
        notes="",
        app_identifiers=("discord",),
        auth_strategy_json=None,
        totp=TotpConfig(secret_base32=FAKE_TOTP_SECRET),
    )


def test_login_engine_run_never_logs_password_or_totp(caplog):
    caplog.set_level(logging.DEBUG)
    engine = LoginEngine(RecordingBackend(), sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")
    totp_code = generate_totp(account.totp)

    engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    for record in caplog.records:
        message = record.getMessage()
        assert FAKE_PASSWORD not in message
        assert totp_code not in message
        assert FAKE_TOTP_SECRET not in message


def test_login_engine_wipes_password_so_a_later_log_cannot_leak_it():
    engine = LoginEngine(RecordingBackend(), sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")

    engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    # Even if something downstream tried to log the account object, the
    # password is gone -- to_str() raises rather than returning stale data.
    with pytest.raises(ValueError):
        account.password.to_str()


# -- udisks: structurally cannot leak a LUKS passphrase --------------------


def test_unlock_function_has_no_password_parameter():
    # This is a structural guarantee, not just a convention: the unlock()
    # function signature physically cannot accept a passphrase, because
    # udisksctl owns that prompt directly (see docs/THREAT_MODEL.md).
    sig = inspect.signature(udisks.unlock)
    assert "password" not in sig.parameters
    assert "passphrase" not in sig.parameters


def test_unlock_subprocess_call_never_includes_extra_arguments(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        from types import SimpleNamespace

        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("passman.integration.usb.udisks.subprocess.run", fake_run)
    udisks.unlock("/dev/sdb1")
    assert captured["args"] == ["udisksctl", "unlock", "-b", "/dev/sdb1"]


# -- recovery codes: only ever handled as opaque strings, never logged ----


def test_recovery_code_serialization_never_touches_logging(caplog):
    caplog.set_level(logging.DEBUG)
    from passman.core.recovery.codes import serialize
    from passman.core.vault.models import RecoveryCode

    serialize([RecoveryCode(code=FAKE_RECOVERY_CODE)])
    for record in caplog.records:
        assert FAKE_RECOVERY_CODE not in record.getMessage()


# -- no plaintext temp files -------------------------------------------------


def test_password_generation_never_writes_a_temp_file(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    from passman.core.generator import generate_random_password, RandomPasswordPolicy

    pw = generate_random_password(RandomPasswordPolicy(length=32))
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert pw not in f.read_text(errors="ignore")


def test_login_run_never_writes_a_temp_file(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    engine = LoginEngine(RecordingBackend(), sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")

    engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    for f in tmp_path.rglob("*"):
        if f.is_file():
            content = f.read_bytes()
            assert FAKE_PASSWORD.encode() not in content


def test_kdbx_file_bytes_never_contain_plaintext_password_or_totp_secret(tmp_path):
    pytest.importorskip("pykeepass")
    from passman.core.vault.kdbx import create_vault
    from passman.core.totp.totp import TotpConfig as TC

    vault_path = tmp_path / "Passwords.kdbx"
    key_path = tmp_path / "Key.key"
    handle = create_vault(vault_path, key_path, password=None)
    uuid = handle.create_account("Demo Discord", "Discord", "demo.user", FAKE_PASSWORD)
    handle.set_totp(uuid, TC(secret_base32=FAKE_TOTP_SECRET))
    handle.save()
    handle.close()

    raw = vault_path.read_bytes()
    assert FAKE_PASSWORD.encode() not in raw
    assert FAKE_TOTP_SECRET.encode() not in raw
