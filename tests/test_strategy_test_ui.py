"""Exercise target handoff without a display, personal vault, or real input."""

from types import SimpleNamespace

import pytest

from passman.core.auth.detection import DetectedContext
from passman.core.auth.engine import LoginOutcome


@pytest.fixture(params=["test", "account"])
def test_editor(monkeypatch, request):
    from passman.ui import account_detail, strategy_editor
    from passman.config.store import Settings
    from passman.core.auth.strategy import PASSWORD_ONLY_STRATEGY
    from passman.core.auth.test_run import build_fake_secrets
    from passman.input.backend import BackendOutcome, InputResult

    mod = strategy_editor if request.param == "test" else account_detail
    flag = "_test_running" if request.param == "test" else "_autotype_running"
    events, timers, jobs, alerts, typed = [], [], [], [], []
    issued = []
    state = SimpleNamespace(unlocked=True, context=DetectedContext("example", "Login", "0x111"))

    def read_account(entry_uuid):
        account = build_fake_secrets(entry_uuid, "Synthetic", "Synthetic", (), False)
        account.auth_strategy_json = PASSWORD_ONLY_STRATEGY.to_json()
        issued.append(account)
        return account

    class Window:
        def set_visible(self, visible):
            events.append(("visible", visible))

        def present(self):
            events.append("present")

    parent = Window()

    class Alert:
        def __init__(self, **kwargs):
            alerts.append(self)

        def add_response(self, *args):
            pass

        def set_default_response(self, response):
            assert response == "cancel"

        set_close_response = set_default_response

        def set_response_appearance(self, *args):
            pass

        def connect(self, signal, callback):
            self.respond = lambda response: callback(self, response)

        def present(self, parent):
            pass

    backend = SimpleNamespace(
        type_text=lambda text: (typed.append(text), BackendOutcome(InputResult.OK))[1],
        press_key=lambda key: BackendOutcome(InputResult.OK),
    )
    def get_context():
        events.append("context")
        return state.context

    def schedule(work, done, **kwargs):
        jobs.append((work, done, kwargs))

    monkeypatch.setattr(mod, "Gtk", SimpleNamespace(Window=Window))
    monkeypatch.setattr(mod, "Adw", SimpleNamespace(AlertDialog=Alert, ResponseAppearance=SimpleNamespace(SUGGESTED=1), Toast=lambda **kwargs: kwargs["title"]))
    monkeypatch.setattr(mod.GLib, "timeout_add", lambda delay, callback: timers.append((delay, callback)))
    monkeypatch.setattr(mod, "run_blocking_async", schedule)
    monkeypatch.setattr(mod, "select_backend", lambda **kwargs: backend)
    monkeypatch.setattr(mod, "get_active_window_context", get_context)
    editor = SimpleNamespace(
        _test_running=False,
        _autotype_running=False,
        _app=SimpleNamespace(settings=Settings(), session=SimpleNamespace(is_unlocked=lambda: state.unlocked, clipboard=object(), vault=lambda: SimpleNamespace(get_account_secrets=read_account))),
        _steps=PASSWORD_ONLY_STRATEGY.steps, _strategy_name="password_only",
        _entry_uuid="fake", _display_name="Fake", _service_name="Fake", _app_identifiers=(),
        _account_has_totp=False, get_root=lambda: parent,
        _test_result_label=SimpleNamespace(set_text=lambda value: events.append(("label", value))),
        _render_test_result=lambda result: events.append(result.outcome),
        _toast=SimpleNamespace(add_toast=events.append),
    )
    invoke = mod.StrategyEditorDialog._on_test_strategy if request.param == "test" else mod.AccountDetailDialog._on_autotype
    return SimpleNamespace(
        mod=mod, editor=editor, state=state, events=events, timers=timers,
        jobs=jobs, alerts=alerts, typed=typed, issued=issued,
        invoke=lambda: invoke(editor, None), busy=lambda: getattr(editor, flag),
        response="test" if request.param == "test" else "type",
        success=LoginOutcome.SUCCESS if request.param == "test" else "Auto-Type sequence completed",
    )


def start(env):
    env.invoke()
    env.alerts[0].respond(env.response)


def test_test_waits_for_target_after_hiding_editor_and_types_only_fake_password(test_editor):
    env = test_editor
    start(env)
    assert ("visible", False) in env.events
    assert "context" not in env.events and env.jobs == [] and env.typed == []
    assert env.issued == []  # no account read before confirmation and target handoff
    assert env.timers[0][0] == 5000
    assert env.timers[0][1]() is False
    work, done, _ = env.jobs[0]
    done(work())
    assert env.typed == [b"test-password-not-real"]
    assert env.success in env.events and env.events[-1] == "present"
    assert not env.busy()
    assert all(not account.password for account in env.issued)


def test_test_cancel_sends_no_input_and_duplicate_clicks_are_ignored(test_editor):
    env = test_editor
    env.invoke()
    env.invoke()
    assert len(env.alerts) == 1
    env.alerts[0].respond("cancel")
    assert not env.busy() and env.issued == []
    assert env.timers == [] and env.jobs == [] and env.typed == []


@pytest.mark.parametrize("stage", ["confirmation", "countdown", "worker"])
def test_lock_during_test_handoff_sends_no_input_or_restores_window(test_editor, stage):
    env = test_editor
    env.invoke()
    if stage == "confirmation":
        env.state.unlocked = False
    env.alerts[0].respond(env.response)
    if stage == "countdown":
        env.state.unlocked = False
    if env.timers:
        env.timers[0][1]()
    if stage == "worker":
        env.state.unlocked = False
        work, done, _ = env.jobs[0]
        done(work())
    assert env.typed == [] and "present" not in env.events
    assert not env.busy() and env.issued == []


def test_worker_error_restores_editor_and_hides_exception_detail(test_editor):
    env = test_editor
    start(env)
    env.timers[0][1]()
    _, _, kwargs = env.jobs[0]
    kwargs["on_error"](RuntimeError("synthetic-sensitive-error"))
    assert env.events[-1] == "present" and not env.busy()
    assert "synthetic-sensitive-error" not in repr(env.events)


def test_missing_target_does_not_type_and_restores_editor(test_editor):
    env = test_editor
    start(env)
    env.timers[0][1]()
    env.state.context = DetectedContext(None, None)
    work, _, kwargs = env.jobs[0]
    with pytest.raises(RuntimeError) as error:
        work()
    kwargs["on_error"](error.value)
    assert env.typed == [] and env.events[-1] == "present"
