""""Test Strategy" execution: runs a strategy end-to-end against fake,
never-real credentials, so a user can verify the step sequence/timing
against a real target without ever risking their real password/TOTP.

This is the direct fix for the exact failure mode observed live: a
strategy running with real secrets into an unconfirmed/ambiguous target.
Test runs use fixed placeholder text and a well-known, publicly
documented test-vector TOTP secret (the same one used throughout this
project's demo vault and tests) -- never the account's real secret, even
when testing a real account's strategy. The Safety Guard still applies
in full: an ambiguous/unknown target still requires confirmation here,
exactly as it would for a real run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..security.memory import SecretBytes
from ..totp.totp import TotpConfig
from ..vault.models import AccountSecrets
from .detection import Confidence, DetectedContext
from .engine import (
    GuardDecision,
    LoginEngine,
    LoginOutcome,
    SafetyGuardMode,
    confidence_for_account,
    evaluate_safety_guard,
)
from .strategy import AuthStep, AuthStrategy
from .strategy_editor import STEP_LABELS

# RFC 4648 test vector, publicly documented -- not a real secret, and
# never the account's own TOTP seed.
FAKE_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
FAKE_USERNAME = "test-username"
FAKE_PASSWORD = "test-password-not-real"


@dataclass(frozen=True)
class StepReport:
    label: str
    ok: bool


@dataclass(frozen=True)
class TestRunResult:
    outcome: LoginOutcome
    detail: str
    confidence: Confidence
    guard_decision: GuardDecision
    steps: list[StepReport] = field(default_factory=list)


def build_fake_secrets(
    entry_uuid: str,
    display_name: str,
    service_name: str,
    app_identifiers: tuple[str, ...],
    include_totp: bool,
) -> AccountSecrets:
    """Construct a placeholder ``AccountSecrets`` for testing -- never
    reads the real account's password or TOTP secret. Callers should
    fetch ``app_identifiers`` via ``VaultHandle.get_app_identifiers()``
    (non-secret), not ``get_account_secrets()``."""
    return AccountSecrets(
        entry_uuid=entry_uuid,
        display_name=display_name,
        service_name=service_name,
        username=FAKE_USERNAME,
        password=SecretBytes(FAKE_PASSWORD),
        url="",
        notes="",
        app_identifiers=app_identifiers,
        auth_strategy_json=None,
        totp=TotpConfig(secret_base32=FAKE_TOTP_SECRET) if include_totp else None,
    )


def run_test(
    backend,
    strategy: AuthStrategy,
    context: DetectedContext,
    guard_mode: SafetyGuardMode,
    *,
    entry_uuid: str,
    display_name: str,
    service_name: str,
    app_identifiers: tuple[str, ...],
    include_totp: bool,
    confirmed: bool = False,
    sleep_fn=time.sleep,
) -> TestRunResult:
    """Run ``strategy`` with fake secrets and report the outcome plus a
    per-step OK/FAILED breakdown (labels only, never typed values)."""
    secrets = build_fake_secrets(entry_uuid, display_name, service_name, app_identifiers, include_totp)
    confidence = confidence_for_account(context, secrets)
    guard_decision = evaluate_safety_guard(guard_mode, confidence)

    reports: list[StepReport] = []

    def on_step(step: AuthStep, ok: bool) -> None:
        reports.append(StepReport(label=STEP_LABELS.get(step.action, step.action.value), ok=ok))

    engine = LoginEngine(backend, sleep_fn=sleep_fn)
    result = engine.run(secrets, strategy, context, guard_mode, confirmed=confirmed, on_step=on_step)
    return TestRunResult(
        outcome=result.outcome,
        detail=result.detail,
        confidence=confidence,
        guard_decision=guard_decision,
        steps=reports,
    )
