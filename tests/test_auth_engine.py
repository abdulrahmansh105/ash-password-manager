"""Safety Guard decision matrix + login-strategy executor, against a
fake input backend (no real ydotool/AT-SPI involved). Uses only fake
account data."""

from __future__ import annotations

from passman.core.auth.detection import Confidence, DetectedContext
from passman.core.auth.engine import (
    GuardDecision,
    LoginEngine,
    LoginOutcome,
    SafetyGuardMode,
    evaluate_safety_guard,
)
from passman.core.auth.strategy import DEFAULT_STRATEGY
from passman.core.security.memory import SecretBytes
from passman.core.totp.totp import TotpConfig
from passman.core.vault.models import AccountSecrets
from passman.input.backend import AuthInputBackend, BackendOutcome, InputResult

FAKE_TOTP_SECRET = "JBSWY3DPEHPK3PXP"


class FakeBackend(AuthInputBackend):
    name = "fake"

    def __init__(self, fail_on: str | None = None) -> None:
        self.typed: list[bytes] = []
        self.keys: list[str] = []
        self.combos: list[str] = []
        self._fail_on = fail_on

    def is_available(self) -> bool:
        return True

    def type_text(self, secret: bytes) -> BackendOutcome:
        self.typed.append(secret)
        if self._fail_on == "type":
            return BackendOutcome(InputResult.FAILED)
        return BackendOutcome(InputResult.OK)

    def press_key(self, key: str) -> BackendOutcome:
        self.keys.append(key)
        if self._fail_on == "key":
            return BackendOutcome(InputResult.FAILED)
        return BackendOutcome(InputResult.OK)

    def press_combo(self, combo: str) -> BackendOutcome:
        self.combos.append(combo)
        return BackendOutcome(InputResult.OK)


def _fake_account(with_totp: bool = True) -> AccountSecrets:
    return AccountSecrets(
        entry_uuid="fake-uuid",
        display_name="Demo Discord",
        service_name="Discord",
        username="demo.user",
        password=SecretBytes("fake-password-123"),
        url="https://discord.com",
        notes="",
        app_identifiers=("discord",),
        auth_strategy_json=None,
        totp=TotpConfig(secret_base32=FAKE_TOTP_SECRET) if with_totp else None,
    )


# -- Safety Guard decision matrix -----------------------------------------


def test_high_confidence_auto_mode_proceeds():
    assert evaluate_safety_guard(SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, Confidence.HIGH) == GuardDecision.PROCEED


def test_low_confidence_always_confirms_even_in_auto_mode():
    assert evaluate_safety_guard(SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, Confidence.LOW) == GuardDecision.CONFIRM_REQUIRED


def test_unknown_confidence_always_confirms_even_in_auto_mode():
    assert evaluate_safety_guard(SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, Confidence.UNKNOWN) == GuardDecision.CONFIRM_REQUIRED


def test_always_confirm_mode_confirms_even_high_confidence():
    assert evaluate_safety_guard(SafetyGuardMode.ALWAYS_CONFIRM, Confidence.HIGH) == GuardDecision.CONFIRM_REQUIRED


def test_no_mode_ever_auto_proceeds_for_unknown_target():
    for mode in SafetyGuardMode:
        assert evaluate_safety_guard(mode, Confidence.UNKNOWN) == GuardDecision.CONFIRM_REQUIRED


# -- LoginEngine ------------------------------------------------------------


def test_login_runs_full_strategy_on_high_confidence_match():
    backend = FakeBackend()
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")

    result = engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    assert result.outcome == LoginOutcome.SUCCESS
    assert len(backend.typed) == 3  # username, password, totp
    assert backend.keys.count("tab") == 1
    assert backend.keys.count("enter") == 2


def test_login_never_types_into_unknown_window_without_confirmation():
    backend = FakeBackend()
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="some-other-app", window_title="Unrelated Window")

    result = engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    assert result.outcome == LoginOutcome.NEEDS_CONFIRMATION
    assert backend.typed == []  # nothing was ever typed


def test_login_proceeds_after_explicit_confirmation():
    backend = FakeBackend()
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="some-other-app", window_title="Unrelated Window")

    result = engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=True)

    assert result.outcome == LoginOutcome.SUCCESS
    assert len(backend.typed) == 3


def test_password_is_wiped_after_run_regardless_of_outcome():
    backend = FakeBackend()
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")

    engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    assert bool(account.password) is False  # SecretBytes.__bool__ is False once wiped


def test_no_totp_configured_skips_totp_step_without_failing():
    backend = FakeBackend()
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account(with_totp=False)
    context = DetectedContext(app_id="discord", window_title="Discord")

    result = engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    assert result.outcome == LoginOutcome.SUCCESS
    assert len(backend.typed) == 2  # username, password only


def test_failed_step_reports_failure_not_exception():
    backend = FakeBackend(fail_on="type")
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")

    result = engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    assert result.outcome == LoginOutcome.FAILED


def test_no_backend_available_reports_no_backend_not_silent_success():
    engine = LoginEngine(None, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")

    result = engine.run(account, DEFAULT_STRATEGY, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    assert result.outcome == LoginOutcome.NO_BACKEND


# -- disabled steps + on_step reporting (strategy editor support) -----------


def test_disabled_step_is_skipped_entirely():
    from passman.core.auth.strategy import AuthStep, AuthStrategy, StepAction

    backend = FakeBackend()
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")
    strategy = AuthStrategy(
        steps=(
            AuthStep(action=StepAction.TYPE_USERNAME),
            AuthStep(action=StepAction.KEY_TAB, enabled=False),
            AuthStep(action=StepAction.TYPE_PASSWORD),
        )
    )

    result = engine.run(account, strategy, context, SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE, confirmed=False)

    assert result.outcome == LoginOutcome.SUCCESS
    assert backend.keys == []  # the disabled Tab step never reached the backend
    assert len(backend.typed) == 2


def test_on_step_callback_reports_each_enabled_step_without_secret_values():
    backend = FakeBackend()
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")
    reports = []

    engine.run(
        account,
        DEFAULT_STRATEGY,
        context,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        confirmed=False,
        on_step=lambda step, ok: reports.append((step.action, ok)),
    )

    assert len(reports) == len(DEFAULT_STRATEGY.steps)
    assert all(ok for _action, ok in reports)


def test_on_step_callback_not_called_for_disabled_steps():
    from passman.core.auth.strategy import AuthStep, AuthStrategy, StepAction

    backend = FakeBackend()
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")
    strategy = AuthStrategy(
        steps=(
            AuthStep(action=StepAction.TYPE_PASSWORD),
            AuthStep(action=StepAction.KEY_TAB, enabled=False),
        )
    )
    reports = []

    engine.run(
        account,
        strategy,
        context,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        confirmed=False,
        on_step=lambda step, ok: reports.append(step.action),
    )

    assert reports == [StepAction.TYPE_PASSWORD]


def test_on_step_stops_at_first_failure_and_reports_it():
    backend = FakeBackend(fail_on="type")
    engine = LoginEngine(backend, sleep_fn=lambda _s: None)
    account = _fake_account()
    context = DetectedContext(app_id="discord", window_title="Discord")
    reports = []

    engine.run(
        account,
        DEFAULT_STRATEGY,
        context,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        confirmed=False,
        on_step=lambda step, ok: reports.append(ok),
    )

    assert reports == [False]  # first step (type username) failed, reported, then run() returned
