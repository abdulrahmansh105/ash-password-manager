"""Tests for the "Test Strategy" safe runner (core/auth/test_run.py) --
the direct fix for the failure mode observed live: this must NEVER use
an account's real password/TOTP, only fixed fake placeholders, while
still enforcing the real Safety Guard."""

from __future__ import annotations

from passman.core.auth.detection import Confidence, DetectedContext
from passman.core.auth.engine import GuardDecision, LoginOutcome, SafetyGuardMode
from passman.core.auth.strategy import DEFAULT_STRATEGY
from passman.core.auth.test_run import (
    FAKE_PASSWORD,
    FAKE_TOTP_SECRET,
    FAKE_USERNAME,
    build_fake_secrets,
    run_test,
)
from passman.input.backend import AuthInputBackend, BackendOutcome, InputResult


class RecordingBackend(AuthInputBackend):
    name = "recording"

    def __init__(self) -> None:
        self.typed: list[bytes] = []

    def is_available(self) -> bool:
        return True

    def type_text(self, secret: bytes) -> BackendOutcome:
        self.typed.append(secret)
        return BackendOutcome(InputResult.OK)

    def press_key(self, key: str) -> BackendOutcome:
        return BackendOutcome(InputResult.OK)

    def press_combo(self, combo: str) -> BackendOutcome:
        return BackendOutcome(InputResult.OK)


def test_build_fake_secrets_never_uses_real_values():
    secrets = build_fake_secrets("uuid-1", "Real Display Name", "RealService", ("re:RealService",), include_totp=True)
    assert secrets.username == FAKE_USERNAME
    assert secrets.password.to_str() == FAKE_PASSWORD
    assert secrets.totp.secret_base32 == FAKE_TOTP_SECRET


def test_build_fake_secrets_omits_totp_when_account_has_none():
    secrets = build_fake_secrets("uuid-1", "X", "Y", (), include_totp=False)
    assert secrets.totp is None


def test_run_test_types_only_fake_values(monkeypatch):
    backend = RecordingBackend()
    context = DetectedContext(app_id="my-app", window_title="My App")
    result = run_test(
        backend,
        DEFAULT_STRATEGY,
        context,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        entry_uuid="uuid-1",
        display_name="Real Discord",
        service_name="Discord",
        app_identifiers=("my-app",),  # matches context -> HIGH confidence
        include_totp=True,
        confirmed=False,
        sleep_fn=lambda _s: None,
    )
    assert result.outcome == LoginOutcome.SUCCESS
    assert result.confidence == Confidence.HIGH
    assert result.guard_decision == GuardDecision.PROCEED
    typed_values = [b.decode() for b in backend.typed]
    assert FAKE_USERNAME in typed_values
    assert FAKE_PASSWORD in typed_values
    # TOTP code itself varies by time, but must never be a real secret
    # -- generated from the well-known fake seed, never the real account's.
    assert len(backend.typed) == 3  # username, password, totp


def test_run_test_still_requires_confirmation_for_unknown_target():
    backend = RecordingBackend()
    context = DetectedContext(app_id="unrelated-app", window_title="Unrelated")
    result = run_test(
        backend,
        DEFAULT_STRATEGY,
        context,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        entry_uuid="uuid-1",
        display_name="Real Discord",
        service_name="Discord",
        app_identifiers=("discord",),  # does not match context
        include_totp=True,
        confirmed=False,
        sleep_fn=lambda _s: None,
    )
    assert result.outcome == LoginOutcome.NEEDS_CONFIRMATION
    assert result.guard_decision == GuardDecision.CONFIRM_REQUIRED
    assert backend.typed == []  # nothing typed -- fake or otherwise


def test_run_test_reports_each_step_without_secret_values():
    backend = RecordingBackend()
    context = DetectedContext(app_id="my-app", window_title="My App")
    result = run_test(
        backend,
        DEFAULT_STRATEGY,
        context,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        entry_uuid="uuid-1",
        display_name="Real Discord",
        service_name="Discord",
        app_identifiers=("my-app",),
        include_totp=True,
        confirmed=False,
        sleep_fn=lambda _s: None,
    )
    assert len(result.steps) == len(DEFAULT_STRATEGY.steps)
    assert all(s.ok for s in result.steps)
    labels = [s.label for s in result.steps]
    assert "Type Username" in labels
    assert "Type Password" in labels
    assert "Type TOTP" in labels
    # Report objects carry only a label + ok flag -- structurally no
    # field could hold a typed value.
    for step_report in result.steps:
        assert not hasattr(step_report, "value")


def test_run_test_confirmed_true_proceeds_even_for_unknown_target():
    # Mirrors the real confirmation flow: after the user has explicitly
    # confirmed, the test run proceeds -- but only with fake secrets.
    backend = RecordingBackend()
    context = DetectedContext(app_id="unrelated-app", window_title="Unrelated")
    result = run_test(
        backend,
        DEFAULT_STRATEGY,
        context,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        entry_uuid="uuid-1",
        display_name="Real Discord",
        service_name="Discord",
        app_identifiers=("discord",),
        include_totp=True,
        confirmed=True,
        sleep_fn=lambda _s: None,
    )
    assert result.outcome == LoginOutcome.SUCCESS
    typed_values = [b.decode() for b in backend.typed]
    assert FAKE_USERNAME in typed_values
    assert FAKE_PASSWORD in typed_values
