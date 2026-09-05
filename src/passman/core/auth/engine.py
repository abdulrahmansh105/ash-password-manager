"""Login strategy executor + the Safety Guard.

The Safety Guard is the single choke point that decides whether an
autotype run may proceed without an interactive confirmation. Per the
user's explicit direction:

- High-confidence target match -> proceed automatically (configurable).
- Ambiguous/unknown target -> ALWAYS require confirmation, regardless of
  the configured mode. There is no setting that can disable this for an
  unrecognized window -- that path does not exist in this code, not just
  "defaults to off".
- The only thing Settings can configure is whether HIGH-confidence
  matches still ask (``SafetyGuardMode.ALWAYS_CONFIRM``) or proceed
  straight through (``SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE``, default).

``LoginEngine.run()`` never receives the plain password as a Python
``str`` from the vault layer -- it works with ``AccountSecrets`` whose
password is ``SecretBytes``, and wipes it in a ``finally`` block after
the run, success or failure.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from ..totp.totp import generate_totp
from ..vault.models import AccountSecrets
from .detection import Confidence, DetectedContext, match_confidence
from .strategy import AuthStep, AuthStrategy, StepAction


class SafetyGuardMode(str, Enum):
    AUTO_ON_HIGH_CONFIDENCE = "auto_high_confidence"
    ALWAYS_CONFIRM = "always_confirm"


class GuardDecision(Enum):
    PROCEED = "proceed"
    CONFIRM_REQUIRED = "confirm_required"


def evaluate_safety_guard(
    mode: SafetyGuardMode, confidence: Confidence
) -> GuardDecision:
    """The one function that decides auto-proceed vs. confirm. Kept tiny
    and pure so it's trivially testable and trivially auditable."""
    if confidence != Confidence.HIGH:
        return GuardDecision.CONFIRM_REQUIRED
    if mode == SafetyGuardMode.ALWAYS_CONFIRM:
        return GuardDecision.CONFIRM_REQUIRED
    return GuardDecision.PROCEED


def confidence_for_account(context: DetectedContext, secrets: AccountSecrets) -> Confidence:
    return match_confidence(context, secrets.app_identifiers)


class LoginOutcome(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    NO_BACKEND = "no_backend"
    NEEDS_CONFIRMATION = "needs_confirmation"


@dataclass(frozen=True)
class LoginResult:
    outcome: LoginOutcome
    detail: str  # non-sensitive only, safe to show/log


class LoginEngine:
    """Executes an ``AuthStrategy`` against an input backend using the
    secrets from one ``AccountSecrets``. Stateless aside from the
    injected backend/sleep function (sleep is injectable for tests)."""

    def __init__(self, backend, sleep_fn=time.sleep) -> None:
        self._backend = backend
        self._sleep = sleep_fn

    def run(
        self,
        secrets: AccountSecrets,
        strategy: AuthStrategy,
        context: DetectedContext,
        guard_mode: SafetyGuardMode,
        confirmed: bool = False,
        on_step: Callable[[AuthStep, bool], None] | None = None,
    ) -> LoginResult:
        """Run ``strategy``. If the Safety Guard requires confirmation
        and ``confirmed`` is not True, returns NEEDS_CONFIRMATION without
        typing anything -- callers (the UI) re-invoke with
        ``confirmed=True`` only after the user has explicitly proceeded.

        ``on_step``, if given, is called after each *enabled* step with
        ``(step, ok)`` -- never with any typed value -- so a caller (the
        strategy editor's "Test Strategy" action) can render a live
        per-step report without ever seeing secret content. Disabled
        steps (``AuthStep.enabled is False``) are skipped entirely and
        never reach ``on_step`` or the backend."""
        confidence = confidence_for_account(context, secrets)
        decision = evaluate_safety_guard(guard_mode, confidence)
        if decision == GuardDecision.CONFIRM_REQUIRED and not confirmed:
            return LoginResult(LoginOutcome.NEEDS_CONFIRMATION, "target confidence not high")

        if self._backend is None:
            return LoginResult(LoginOutcome.NO_BACKEND, "no input backend available")

        try:
            for step in strategy.steps:
                if not step.enabled:
                    continue
                ok = self._run_step(step, secrets)
                if on_step is not None:
                    on_step(step, ok)
                if not ok:
                    return LoginResult(LoginOutcome.FAILED, f"step failed: {step.action.value}")
            return LoginResult(LoginOutcome.SUCCESS, "login sequence completed")
        finally:
            secrets.wipe()

    def _run_step(self, step: AuthStep, secrets: AccountSecrets) -> bool:
        if step.action == StepAction.TYPE_USERNAME:
            return self._type(secrets.username.encode("utf-8"))
        if step.action == StepAction.TYPE_PASSWORD:
            return self._type(secrets.password.to_bytes())
        if step.action == StepAction.TYPE_TOTP:
            if secrets.totp is None:
                return True  # no TOTP configured for this account: skip, don't fail
            code = generate_totp(secrets.totp)
            ok = self._type(code.encode("utf-8"))
            code = "0" * len(code)  # best-effort overwrite of the local var
            del code
            return ok
        if step.action == StepAction.KEY_TAB:
            return self._backend.press_key("tab").result.value == "ok"
        if step.action == StepAction.KEY_ENTER:
            return self._backend.press_key("enter").result.value == "ok"
        if step.action == StepAction.KEY_ESCAPE:
            return self._backend.press_key("escape").result.value == "ok"
        if step.action == StepAction.KEY_COMBO:
            return self._backend.press_combo(step.value or "").result.value == "ok"
        if step.action == StepAction.WAIT:
            ms = int(step.value or "0")
            self._sleep(ms / 1000.0)
            return True
        if step.action == StepAction.FOCUS_FIELD:
            outcome = self._backend.focus_field(step.field_hint)
            # Not fatal if unsupported -- the executor just proceeds and
            # relies on prior Tab navigation / already-focused field.
            return True if outcome.result.value != "failed" else False
        return False

    def _type(self, data: bytes) -> bool:
        outcome = self._backend.type_text(data)
        return outcome.result.value == "ok"
