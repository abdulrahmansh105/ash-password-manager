"""Single entry activation and confirmation, with only fabricated credentials."""

from types import SimpleNamespace

import pytest

from passman.core.auth.detection import DetectedContext
from passman.core.auth.strategy import PASSWORD_ONLY_STRATEGY
from passman.core.auth.test_run import build_fake_secrets
from passman.input.backend import BackendOutcome, InputResult


@pytest.fixture
def env(monkeypatch):
    from passman.config.store import Settings
    from passman.ui import autotype as mod

    events, timers, jobs, alerts, typed, issued = [], [], [], [], [], []
    target = DetectedContext("example", "Login", "0x111")
    state = SimpleNamespace(unlocked=True, current=target, focus_ok=True)
    app = SimpleNamespace(settings=Settings(), detected_context=target)

    def read(entry_uuid):
        account = build_fake_secrets(entry_uuid, "Fake", "Fake", (), False)
        account.auth_strategy_json = PASSWORD_ONLY_STRATEGY.to_json()
        issued.append(account)
        return account

    app.session = SimpleNamespace(
        is_unlocked=lambda: state.unlocked, clipboard=object(),
        vault=lambda: SimpleNamespace(get_account_secrets=read),
    )
    parent = SimpleNamespace(
        set_visible=lambda value: events.append(("visible", value)),
        present=lambda: events.append("present"),
        _toast_overlay=SimpleNamespace(add_toast=events.append),
    )

    class Alert:
        def __init__(self, **kwargs):
            self.options = kwargs
            self.responses = {}
            alerts.append(self)

        def add_response(self, key, label):
            self.responses[key] = label

        def set_default_response(self, response):
            assert response == "cancel"

        set_close_response = set_default_response

        def set_response_appearance(self, *args):
            pass

        def connect(self, signal, callback):
            self.respond = lambda response: callback(self, response)

        def present(self, owner):
            assert owner is parent

    backend = SimpleNamespace(
        type_text=lambda text: (typed.append(text), BackendOutcome(InputResult.OK))[1],
        press_key=lambda key: BackendOutcome(InputResult.OK),
    )
    monkeypatch.setattr(mod, "Adw", SimpleNamespace(
        AlertDialog=Alert, ResponseAppearance=SimpleNamespace(SUGGESTED=1),
        Toast=lambda **kwargs: kwargs["title"],
    ))
    monkeypatch.setattr(mod.GLib, "timeout_add", lambda delay, callback: timers.append((delay, callback)))
    monkeypatch.setattr(mod, "run_blocking_async", lambda work, done, **kw: jobs.append((work, done, kw)))
    monkeypatch.setattr(mod, "select_backend", lambda **kwargs: backend)
    monkeypatch.setattr(mod, "get_active_window_context", lambda: state.current)
    monkeypatch.setattr(mod, "focus_target_window", lambda ctx: (events.append(("focus", ctx)), state.focus_ok)[1])
    controller = mod.AccountAutoType(app)
    return SimpleNamespace(**locals())


def start(env):
    env.controller.request(env.parent, "fake", "Example account")
    assert env.alerts[0].responses == {"cancel": "Cancel", "yes": "Yes"}
    assert env.issued == [] and env.typed == []
    env.alerts[0].respond("yes")
    env.timers[0][1]()


def complete(env):
    work, done, _ = env.jobs[0]
    done(work())


def test_yes_restores_target_runs_saved_strategy_and_leaves_login_in_front(env):
    start(env)
    assert env.timers[0][0] == 250
    complete(env)
    assert env.typed == [b"test-password-not-real"]
    assert ("focus", env.target) in env.events and ("visible", False) in env.events
    assert "present" not in env.events and not env.controller.busy
    assert not env.issued[0].password


def test_cancel_and_duplicate_entry_clicks_never_read_credentials(env):
    env.controller.request(env.parent, "fake", "Fake")
    env.controller.request(env.parent, "other", "Other")
    assert len(env.alerts) == 1
    env.alerts[0].respond("cancel")
    assert not env.controller.busy and env.issued == [] and env.timers == []


@pytest.mark.parametrize("stage", ["prompt", "timer", "worker"])
def test_lock_stops_handoff_without_reading_credentials(env, stage):
    env.controller.request(env.parent, "fake", "Fake")
    if stage == "prompt":
        env.state.unlocked = False
    env.alerts[0].respond("yes")
    if stage == "timer":
        env.state.unlocked = False
    if env.timers:
        env.timers[0][1]()
    if stage == "worker":
        env.state.unlocked = False
        complete(env)
    assert env.issued == [] and env.typed == [] and "present" not in env.events
    assert not env.controller.busy


def test_unrestorable_window_does_not_read_or_type_credentials(env):
    start(env)
    env.state.focus_ok = False
    work, _, kwargs = env.jobs[0]
    with pytest.raises(RuntimeError) as error:
        work()
    kwargs["on_error"](error.value)
    assert env.issued == [] and env.typed == []
    assert env.events[-1] == "present" and not env.controller.busy


def test_unknown_target_uses_five_second_handoff(env):
    env.app.detected_context = None
    start(env)
    assert env.timers[0][0] == 5000
    complete(env)
    assert env.typed and not any(isinstance(e, tuple) and e[0] == "focus" for e in env.events)


def test_unknown_target_must_not_type_into_ash(env):
    env.app.detected_context = None
    env.state.current = DetectedContext("dev.ash.PasswordManager", "ASH", "0x222")
    start(env)
    work, _, kwargs = env.jobs[0]
    with pytest.raises(RuntimeError) as error:
        work()
    kwargs["on_error"](error.value)
    assert not env.issued and not env.typed


def test_window_change_after_focus_stops_typing_and_wipes_secrets(env):
    start(env)
    env.state.current = DetectedContext("example", "Other window", "0x222")
    complete(env)
    assert env.typed == [] and not env.issued[0].password
    assert env.events[-1] == "present"


def test_manager_row_asks_for_autotype_without_opening_account_details(monkeypatch):
    from passman.ui.manager import main_window as mod

    calls = []
    monkeypatch.setattr(mod, "request_autotype", lambda *args: calls.append(args))
    window = SimpleNamespace(app=object())
    row = SimpleNamespace(summary=SimpleNamespace(entry_uuid="fake", display_name="Example"))
    mod.ManagerWindow._on_row_activated(window, None, row)
    assert calls == [(window.app, window, "fake", "Example")]


def test_legacy_picker_uses_same_yes_confirmation(monkeypatch):
    from passman.ui import launcher_window as mod

    calls = []
    monkeypatch.setattr(mod, "request_autotype", lambda *args: calls.append(args))
    window = SimpleNamespace(app=object())
    summary = SimpleNamespace(entry_uuid="fake", display_name="Example")
    mod.AccountPickerWindow._on_account_activated(window, summary)
    assert calls == [(window.app, window, "fake", "Example")]


@pytest.mark.parametrize("address", [None, "0x0", "0x123;bad", "address:0x123"])
def test_focus_rejects_invalid_addresses_without_running_a_command(monkeypatch, address):
    from passman.core.auth import detection

    monkeypatch.setattr(detection.subprocess, "run", lambda *a, **kw: pytest.fail("must not execute"))
    assert not detection.focus_target_window(DetectedContext("example", None, address))


@pytest.mark.parametrize("lua_available", [True, False])
def test_focus_verifies_window_and_supports_current_and_legacy_hyprland(monkeypatch, lua_available):
    from passman.core.auth import detection

    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0 if lua_available or command[1] == "dispatch" else 1)

    target = DetectedContext("example", None, "0x123")
    monkeypatch.setattr(detection.subprocess, "run", run)
    monkeypatch.setattr(detection, "get_active_window_context", lambda: target)
    assert detection.focus_target_window(target)
    assert commands[0][1] == "eval"
    assert (len(commands) == 1) == lua_available


def test_focus_never_trusts_dispatcher_success_without_matching_window(monkeypatch):
    from passman.core.auth import detection

    monkeypatch.setattr(detection.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    monkeypatch.setattr(detection.time, "sleep", lambda _: None)
    monkeypatch.setattr(detection, "get_active_window_context", lambda: DetectedContext("wrong", None, "0x999"))
    assert not detection.focus_target_window(DetectedContext("example", None, "0x123"))
