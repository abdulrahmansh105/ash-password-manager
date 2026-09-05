"""Runs the (synchronous, subprocess/sleep-heavy) login-strategy
executor off the GTK main thread.

Root cause of the "Not Responding" bug this module fixes: ``LoginEngine.
run()`` (``.engine``), ``select_backend()`` (``..input``, which probes
AT-SPI and shells out to ``pgrep`` for ydotoold), and
``get_active_window_context()`` (``.detection``, which shells out to
``hyprctl``) are all plain blocking calls -- ``subprocess.run()`` with
multi-second timeouts, real AT-SPI accessibility-tree walks, and
``time.sleep()`` for WAIT steps. GTK4/GLib's main loop is strictly
single-threaded and cooperative: calling any of these directly from a
signal handler or a ``GLib.timeout_add`` callback -- even a callback
scheduled from one -- freezes input handling and rendering for as long
as the call takes. A strategy with a 1500ms TOTP-rollover wait plus a
couple of ydotool round-trips easily adds up to multi-second freezes,
which is exactly what the desktop reports as "Not Responding".

The fix is the standard GLib-endorsed pattern for this situation: run
the blocking work on a plain background ``threading.Thread``, and
marshal every callback that touches GTK/Adw state back onto the main
thread via ``GLib.idle_add`` -- the only thread-safe way to schedule
work on GLib's main context from another thread. Nothing in this module
imports Gtk/Adw or touches a widget; it only ever calls the callbacks
it is given, and only via ``idle_scheduler``. ``idle_scheduler`` is
injectable (defaults to real ``GLib.idle_add``) specifically so tests
can exercise the "runs off-thread, delivers via a scheduler" contract
without needing a live GTK application or display -- see
``tests/test_async_login.py``.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

from gi.repository import GLib

from ..vault.models import AccountSecrets
from .detection import DetectedContext, get_active_window_context
from .engine import LoginEngine, LoginOutcome, LoginResult, SafetyGuardMode
from .strategy import AuthStrategy

T = TypeVar("T")

# A scheduler takes a zero-argument callback and arranges for it to run
# later on "the right" thread (the GTK main thread, in production).
IdleScheduler = Callable[[Callable[[], None]], None]


def glib_idle_scheduler(callback: Callable[[], None]) -> None:
    """Default ``IdleScheduler``: hands ``callback`` to GLib's main
    context via ``idle_add``, wrapped so it runs exactly once."""

    def _run_once() -> bool:
        callback()
        return False

    GLib.idle_add(_run_once)


def run_blocking_async(
    work_fn: Callable[[], T],
    on_done: Callable[[T], None],
    idle_scheduler: IdleScheduler = glib_idle_scheduler,
) -> threading.Thread:
    """Runs ``work_fn()`` on a new background thread and delivers its
    return value to ``on_done`` on the caller's thread via
    ``idle_scheduler``. Generic escape hatch for blocking operations
    (active-window detection, a strategy test-run) that must not run on
    the GTK main thread but only need to report a final result, not
    step-by-step progress."""

    def worker() -> None:
        result = work_fn()
        idle_scheduler(lambda: on_done(result))

    thread = threading.Thread(target=worker, daemon=True, name="passman-bg-worker")
    thread.start()
    return thread


def run_login_async(
    backend_factory: Callable[[], Any],
    secrets: AccountSecrets,
    strategy: AuthStrategy,
    context: DetectedContext,
    guard_mode: SafetyGuardMode,
    confirmed: bool,
    on_done: Callable[[LoginResult], None],
    sleep_fn: Callable[[float], None] | None = None,
    idle_scheduler: IdleScheduler = glib_idle_scheduler,
) -> threading.Thread:
    """Runs one full sign-in -- backend selection (AT-SPI probe / ydotool
    ``pgrep``), then ``LoginEngine.run()`` (subprocess calls and WAIT-step
    sleeps for every step) -- entirely on a background thread.

    ``backend_factory`` is called on that background thread too (not by
    this function directly), since ``select_backend()`` itself shells
    out. ``on_done`` fires on the caller's thread once the whole
    strategy has finished, success or failure -- GTK callers
    (``ui.launcher_window``, ``ui.strategy_editor``) hand off here and
    return immediately instead of blocking the main loop for the whole
    sign-in sequence."""

    def work() -> LoginResult:
        backend = backend_factory()
        if backend is None:
            return LoginResult(LoginOutcome.NO_BACKEND, "no input backend available")
        engine = LoginEngine(backend, sleep_fn=sleep_fn or time.sleep)
        return engine.run(secrets, strategy, context, guard_mode, confirmed=confirmed)

    return run_blocking_async(work, on_done, idle_scheduler)


def get_active_window_context_async(
    on_done: Callable[[DetectedContext], None],
    idle_scheduler: IdleScheduler = glib_idle_scheduler,
) -> threading.Thread:
    """Background-thread version of ``detection.get_active_window_context``
    (a ``hyprctl`` subprocess call) for callers -- e.g. the strategy
    editor's "Test Strategy" button -- that run it from a live GTK
    session rather than before any main loop exists."""
    return run_blocking_async(get_active_window_context, on_done, idle_scheduler)
