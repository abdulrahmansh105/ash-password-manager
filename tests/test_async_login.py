"""Regression tests for the "Not Responding" bug (spec: full sign-in
must never block the GTK main thread).

None of these import Gtk/Adw or need a display -- they exercise
``core.auth.async_login`` directly, using a real ``GLib.MainLoop``
(headless; GLib's main context needs no display) as a stand-in for the
GTK main thread wherever "the UI keeps responding" needs to be proven,
and a fake, injectable ``idle_scheduler`` everywhere else so the tests
stay fast and deterministic.
"""

from __future__ import annotations

import threading
import time

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib

from passman.core.auth.async_login import (
    get_active_window_context_async,
    run_blocking_async,
    run_login_async,
)
from passman.core.auth.detection import DetectedContext
from passman.core.auth.engine import LoginOutcome, SafetyGuardMode
from passman.core.auth.strategy import AuthStep, AuthStrategy, StepAction
from passman.core.security.memory import SecretBytes
from passman.core.totp.totp import TotpConfig
from passman.core.vault.models import AccountSecrets
from passman.input.backend import AuthInputBackend, BackendOutcome, InputResult

FAKE_TOTP_SECRET = "JBSWY3DPEHPK3PXP"


class RecordingBackend(AuthInputBackend):
    """Records which thread every call landed on, alongside the usual
    call log -- the whole point of these tests is proving backend calls
    never happen on the caller's (i.e. the GTK main) thread."""

    name = "recording"

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.threads: list[int] = []

    def is_available(self) -> bool:
        return True

    def type_text(self, secret: bytes) -> BackendOutcome:
        self.calls.append("type")
        self.threads.append(threading.get_ident())
        return BackendOutcome(InputResult.OK)

    def press_key(self, key: str) -> BackendOutcome:
        self.calls.append(f"key:{key}")
        self.threads.append(threading.get_ident())
        return BackendOutcome(InputResult.OK)

    def press_combo(self, combo: str) -> BackendOutcome:
        self.calls.append(f"combo:{combo}")
        self.threads.append(threading.get_ident())
        return BackendOutcome(InputResult.OK)


def _immediate_scheduler(callback) -> None:
    """A same-thread, run-it-right-now IdleScheduler for tests that
    don't need a real GLib main loop -- keeps most tests simple and
    fast while still exercising the real threading/offload contract."""
    callback()


def _fake_secrets(with_totp: bool = False) -> AccountSecrets:
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


def _wait_strategy(*wait_ms: int) -> AuthStrategy:
    """A strategy shaped exactly like the bug report: type, wait
    (TOTP-rollover-style delay), repeat."""
    steps = []
    for ms in wait_ms:
        steps.append(AuthStep(action=StepAction.TYPE_USERNAME))
        steps.append(AuthStep(action=StepAction.WAIT, value=str(ms)))
    return AuthStrategy(name="test", steps=tuple(steps))


_UNKNOWN_CONTEXT = DetectedContext(app_id=None, window_title=None)


# -- run_blocking_async: the generic building block -----------------------


def test_run_blocking_async_executes_off_the_callers_thread():
    caller_ident = threading.get_ident()
    seen = {}
    done = threading.Event()

    def work():
        seen["ident"] = threading.get_ident()
        return 42

    def on_done(value):
        seen["value"] = value
        done.set()

    run_blocking_async(work, on_done, idle_scheduler=_immediate_scheduler)
    assert done.wait(timeout=5), "background work never completed"
    assert seen["ident"] != caller_ident
    assert seen["value"] == 42


def test_run_blocking_async_returns_to_caller_immediately():
    done = threading.Event()

    def work():
        time.sleep(0.3)
        return "ok"

    start = time.monotonic()
    run_blocking_async(work, lambda _v: done.set(), idle_scheduler=_immediate_scheduler)
    elapsed_to_return = time.monotonic() - start

    # The call above must not have waited for the 300ms of "work" --
    # this is the exact shape of the bug: engine.run() used to execute
    # synchronously inside the GTK callback that invoked it.
    assert elapsed_to_return < 0.05
    assert done.wait(timeout=5)


# -- run_login_async: the actual sign-in path ------------------------------


def test_login_does_not_block_the_caller_even_with_real_sleeps():
    """The literal bug report: WAIT steps (500ms/1500ms/2000ms in the
    field) executed via real time.sleep() must not freeze the caller.
    Durations are shortened here to keep the test fast, but no sleep_fn
    is injected -- this exercises the real time.sleep() code path."""
    strategy = _wait_strategy(150, 200)
    secrets = _fake_secrets()
    backend = RecordingBackend()
    done = threading.Event()
    result_box: list = []

    start = time.monotonic()
    run_login_async(
        lambda: backend,
        secrets,
        strategy,
        _UNKNOWN_CONTEXT,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        confirmed=True,
        on_done=lambda r: (result_box.append(r), done.set()),
        idle_scheduler=_immediate_scheduler,
    )
    elapsed_to_return = time.monotonic() - start

    assert elapsed_to_return < 0.05, "run_login_async blocked the caller"
    assert done.wait(timeout=5), "login never completed in the background"
    assert result_box[0].outcome == LoginOutcome.SUCCESS
    # And the work really did happen, on a different thread than the caller's.
    assert backend.calls.count("type") == 2
    assert all(t != threading.get_ident() for t in backend.threads)


def test_backend_selection_itself_runs_off_the_callers_thread():
    """select_backend() (an AT-SPI probe / ydotool `pgrep`) must also
    not run on the caller's thread -- ``backend_factory`` is called
    inside the worker, not before handing off to it."""
    caller_ident = threading.get_ident()
    factory_thread = {}
    done = threading.Event()

    def backend_factory():
        factory_thread["ident"] = threading.get_ident()
        return RecordingBackend()

    run_login_async(
        backend_factory,
        _fake_secrets(),
        _wait_strategy(50),
        _UNKNOWN_CONTEXT,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        confirmed=True,
        on_done=lambda _r: done.set(),
        idle_scheduler=_immediate_scheduler,
    )
    assert done.wait(timeout=5)
    assert factory_thread["ident"] != caller_ident


def test_no_backend_available_reports_cleanly_without_blocking():
    done = threading.Event()
    result_box: list = []

    run_login_async(
        lambda: None,
        _fake_secrets(),
        _wait_strategy(50),
        _UNKNOWN_CONTEXT,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        confirmed=True,
        on_done=lambda r: (result_box.append(r), done.set()),
        idle_scheduler=_immediate_scheduler,
    )
    assert done.wait(timeout=5)
    assert result_box[0].outcome == LoginOutcome.NO_BACKEND


def test_multiple_delayed_auth_steps_all_run_but_never_block_caller():
    """Several WAIT steps in one strategy (the multi-page / TOTP-rollover
    case) must still add up to real elapsed background time, while the
    call into run_login_async itself stays instant."""
    strategy = _wait_strategy(80, 80, 80)  # three delayed steps
    secrets = _fake_secrets(with_totp=True)
    backend = RecordingBackend()
    done = threading.Event()
    background_start = time.monotonic()
    background_elapsed = {}

    def on_done(_result):
        background_elapsed["seconds"] = time.monotonic() - background_start
        done.set()

    start = time.monotonic()
    run_login_async(
        lambda: backend,
        secrets,
        strategy,
        _UNKNOWN_CONTEXT,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        confirmed=True,
        on_done=on_done,
        idle_scheduler=_immediate_scheduler,
    )
    elapsed_to_return = time.monotonic() - start

    assert elapsed_to_return < 0.05
    assert done.wait(timeout=5)
    # The three waits really executed in sequence in the background
    # (not skipped, not collapsed) -- comfortably more than 3*80ms.
    assert background_elapsed["seconds"] >= 0.2


def test_ui_stays_usable_while_authentication_is_running():
    """Simulates the user continuing to interact with the app (e.g.
    clicking elsewhere) while a login is in flight: those "clicks"
    (plain function calls on the caller's thread) must be able to
    happen freely, unblocked, for the whole duration of the background
    login run."""
    release_worker = threading.Event()
    login_done = threading.Event()
    ui_clicks = []

    def slow_backend_call():
        # Blocks only the *worker* thread until the test has proven the
        # caller thread is still free to do other things.
        release_worker.wait(timeout=5)
        return BackendOutcome(InputResult.OK)

    class BlockingBackend(AuthInputBackend):
        name = "blocking"

        def is_available(self):
            return True

        def type_text(self, secret):
            return slow_backend_call()

        def press_key(self, key):
            return BackendOutcome(InputResult.OK)

        def press_combo(self, combo):
            return BackendOutcome(InputResult.OK)

    strategy = AuthStrategy(name="t", steps=(AuthStep(action=StepAction.TYPE_USERNAME),))
    run_login_async(
        lambda: BlockingBackend(),
        _fake_secrets(),
        strategy,
        _UNKNOWN_CONTEXT,
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        confirmed=True,
        on_done=lambda _r: login_done.set(),
        idle_scheduler=_immediate_scheduler,
    )

    # While the worker thread is still stuck inside the backend call,
    # the caller ("UI thread") does several unrelated things.
    for i in range(20):
        ui_clicks.append(i)
    assert len(ui_clicks) == 20
    assert not login_done.is_set(), "login finished before we ever unblocked it -- test is not exercising the race"

    release_worker.set()
    assert login_done.wait(timeout=5)


def test_context_detection_runs_off_callers_thread(monkeypatch):
    """get_active_window_context() shells out to `hyprctl`; the async
    wrapper used by the strategy editor's Test Strategy button must run
    it off the caller's thread too."""
    caller_ident = threading.get_ident()
    seen = {}
    done = threading.Event()

    def fake_get_context():
        seen["ident"] = threading.get_ident()
        return DetectedContext(app_id="discord", window_title="Discord")

    monkeypatch.setattr("passman.core.auth.async_login.get_active_window_context", fake_get_context)

    get_active_window_context_async(
        lambda ctx: (seen.setdefault("context", ctx), done.set()),
        idle_scheduler=_immediate_scheduler,
    )
    assert done.wait(timeout=5)
    assert seen["ident"] != caller_ident
    assert seen["context"].app_id == "discord"


# -- the flagship test: a real GLib main loop keeps ticking ----------------


def test_glib_main_loop_remains_responsive_during_login():
    """The most direct proof available without an actual GTK window:
    runs a real ``GLib.MainLoop`` (no display needed) with a fast
    repeating heartbeat timeout alongside a real login run (real
    threads, real time.sleep() via the default sleep_fn, real
    ``GLib.idle_add`` for delivery). If ``run_login_async`` ever
    regressed to running the strategy synchronously inside a GLib
    callback -- exactly the original bug -- this heartbeat would stall
    for the run's whole duration and this test would fail."""
    strategy = _wait_strategy(250)  # one real ~250ms sleep in the background
    backend = RecordingBackend()
    loop = GLib.MainLoop()
    heartbeats = {"count": 0}

    def heartbeat() -> bool:
        heartbeats["count"] += 1
        return True  # keep ticking

    def on_login_done(_result) -> None:
        loop.quit()

    heartbeat_source = GLib.timeout_add(20, heartbeat)  # every 20ms
    GLib.timeout_add(
        0,
        lambda: (
            run_login_async(
                lambda: backend,
                _fake_secrets(),
                strategy,
                _UNKNOWN_CONTEXT,
                SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
                confirmed=True,
                on_done=on_login_done,
            ),
            False,
        )[1],
    )

    # Safety net so a real regression fails the test instead of hanging
    # the suite forever.
    GLib.timeout_add(5000, lambda: (loop.quit(), False)[1])

    loop.run()
    GLib.source_remove(heartbeat_source)

    # A blocked main loop would tick the heartbeat ~0 times during the
    # ~250ms WAIT step; a healthy one ticks it roughly 250/20 = ~12
    # times. Require a generous fraction of that as the pass bar.
    assert heartbeats["count"] >= 6, f"GLib main loop stalled during login (only {heartbeats['count']} heartbeats)"
    assert backend.calls == ["type"]
