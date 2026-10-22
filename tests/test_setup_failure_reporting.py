"""A setup worker failure must reach the UI instead of leaving a spinner."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from passman.core.auth.async_login import run_blocking_async
from passman.core.crypto.kdf import INSECURE_FAST_PARAMS_FOR_TESTS_ONLY as FAST
from passman.core.flows.setup_machine import SetupFlow, SetupState
from passman.core.flows.usb_setup import SetupUsbError, require_setup_write_access
from passman.core.security.memory import SecretBytes
from passman.core.vault.provisioning import ProvisioningError, create_new_vault


def test_worker_exception_is_delivered_on_main_thread_after_worker_exits():
    scheduled, errors, values = [], [], []

    def fail():
        raise PermissionError("synthetic USB permission failure")

    worker = run_blocking_async(
        fail, values.append, idle_scheduler=scheduled.append, on_error=errors.append
    )
    worker.join(5)
    assert not worker.is_alive()
    assert values == errors == []
    assert len(scheduled) == 1
    scheduled[0]()  # exception closure remains valid after the except block
    assert len(errors) == 1 and isinstance(errors[0], PermissionError)


def test_permission_failure_creating_staging_is_a_provisioning_error(
    fake_usb, monkeypatch, isolated_xdg
):
    def denied(**kwargs):
        raise PermissionError("synthetic root-owned USB")

    monkeypatch.setattr("passman.core.vault.provisioning.tempfile.mkdtemp", denied)
    with pytest.raises(ProvisioningError, match="Write permission was denied"):
        create_new_vault(
            str(fake_usb),
            "ASH",
            "Synthetic",
            SecretBytes("fake-master"),
            enroll_local_key=False,
            argon2_params=FAST,
        )
    assert list(fake_usb.iterdir()) == []


def test_write_preflight_reports_denied_access_without_changing_usb(
    fake_usb, monkeypatch
):
    monkeypatch.setattr("passman.core.flows.usb_setup.os.access", lambda *args: False)
    with pytest.raises(SetupUsbError, match="cannot write"):
        require_setup_write_access(str(fake_usb), "ASH")
    assert list(fake_usb.iterdir()) == []


def test_write_preflight_handles_real_unwritable_directory(fake_usb):
    import os

    if os.geteuid() == 0:
        pytest.skip("root can bypass the synthetic read-only directory mode")
    fake_usb.chmod(0o555)
    try:
        with pytest.raises(SetupUsbError, match="cannot write"):
            require_setup_write_access(str(fake_usb), "ASH")
        with pytest.raises(ProvisioningError, match="Write permission was denied"):
            create_new_vault(
                str(fake_usb),
                "ASH",
                "Synthetic",
                SecretBytes("fake-master"),
                enroll_local_key=False,
                argon2_params=FAST,
            )
        assert list(fake_usb.iterdir()) == []
    finally:
        fake_usb.chmod(0o700)


def test_write_preflight_checks_parent_for_create_and_container_for_adoption(
    fake_usb, monkeypatch
):
    target = fake_usb / "Legacy"
    target.mkdir()
    inspected = []
    monkeypatch.setattr(
        "passman.core.flows.usb_setup.os.access",
        lambda path, flags: inspected.append(path) or True,
    )
    require_setup_write_access(str(fake_usb), "Legacy")
    require_setup_write_access(str(fake_usb), "Legacy", adopting=True)
    assert inspected == [fake_usb, target]


def test_commit_worker_failure_clears_progress_and_restores_retry_state(monkeypatch):
    from passman.ui.setup.setup_window import SetupWindow
    import passman.ui.setup.setup_window as module

    flow = SetupFlow()
    flow.state = SetupState.LOCAL_KEY_OPTIONAL
    pushed, errors, queued = [], [], []

    def fail():
        raise PermissionError("sensitive-like text must not be displayed")

    window = SimpleNamespace(
        _flow=flow,
        _nav=SimpleNamespace(push=pushed.append, pop=lambda: pushed.pop()),
        _build_progress_page=lambda message: message,
        _commit_work=fail,
        _show_error=errors.append,
    )
    window._on_commit_done = lambda result: SetupWindow._on_commit_done(window, result)
    window._on_commit_error = lambda error: SetupWindow._on_commit_error(window, error)

    def start(work, on_done, *, on_error):
        worker = run_blocking_async(
            work, on_done, idle_scheduler=queued.append, on_error=on_error
        )
        worker.join(5)
        assert not worker.is_alive()

    monkeypatch.setattr(module, "run_blocking_async", start)
    SetupWindow._commit_vault(window)
    assert pushed == ["Creating your vault…"]
    queued[0]()
    assert pushed == [] and flow.state is SetupState.LOCAL_KEY_OPTIONAL
    assert len(errors) == 1 and "PermissionError" in errors[0]
    assert "sensitive-like" not in errors[0]


def test_unwritable_usb_is_rejected_before_password_page(fake_usb, monkeypatch):
    import passman.ui.setup.setup_window as module
    from passman.ui.setup.setup_window import SetupWindow

    identity = object()
    monkeypatch.setattr(
        module, "prepare_mountpoint", lambda *args: (identity, str(fake_usb))
    )
    monkeypatch.setattr(module, "discover_container", lambda mount: ("ASH", "empty"))

    def denied(*args, **kwargs):
        raise SetupUsbError("USB is not writable")

    monkeypatch.setattr(module, "require_setup_write_access", denied)
    window = SimpleNamespace(
        _selected_drive=SimpleNamespace(
            object_path="test", vendor="Fake", model="Synthetic"
        )
    )
    result = SetupWindow._prepare_usb_work(window)
    assert result[:4] == (None, None, None, None) and "not writable" in result[4]


def test_existing_vault_detection_does_not_require_setup_write_access(
    fake_usb, monkeypatch
):
    import passman.ui.setup.setup_window as module
    from passman.ui.setup.setup_window import SetupWindow

    identity = object()
    monkeypatch.setattr(
        module, "prepare_mountpoint", lambda *args: (identity, str(fake_usb))
    )
    monkeypatch.setattr(module, "discover_container", lambda mount: ("ASH", "ash"))

    def forbidden(*args, **kwargs):
        pytest.fail("An existing-vault login must not use the creation permission gate")

    monkeypatch.setattr(module, "require_setup_write_access", forbidden)
    window = SimpleNamespace(
        _selected_drive=SimpleNamespace(
            object_path="test", vendor="Fake", model="Synthetic"
        )
    )
    assert SetupWindow._prepare_usb_work(window) == (
        identity,
        str(fake_usb),
        "ASH",
        "ash",
        None,
    )
