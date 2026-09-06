"""Tests for core.flows.login_machine -- spec section 27's returning-
user login flow, and the hard rule from spec section 1: if a valid
Local Key exists, the password must never be requested."""

from __future__ import annotations

from passman.core.devices.registry import VaultUnreadableError
from passman.core.flows.login_machine import (
    LoginFailureReason,
    LoginFlow,
    LoginState,
    attempt_automatic_login,
)
from passman.core.security.memory import SecretBytes
from passman.core.vaults.registry import VaultRecord

RECORD = VaultRecord(vault_id="v1", name="My Passwords", filesystem_uuid="fs-1")


def _flow(*, identify=None, mount=None, local_key=None, password=None) -> LoginFlow:
    return LoginFlow(
        identify_usb=identify or (lambda: RECORD),
        mount=mount or (lambda record: "/media/usb"),
        unlock_with_local_key=local_key or (lambda record, mp: SecretBytes(b"V" * 32)),
        unlock_with_password=password or (lambda record, mp, pw: SecretBytes(b"V" * 32)),
    )


def test_no_usb_match_fails_immediately():
    flow = _flow(identify=lambda: None)
    outcome = attempt_automatic_login(flow)
    assert outcome.state == LoginState.FAILED
    assert outcome.failure == LoginFailureReason.NO_MATCHING_USB


def test_mount_failure_is_reported():
    flow = _flow(mount=lambda record: None)
    outcome = attempt_automatic_login(flow)
    assert outcome.state == LoginState.FAILED
    assert outcome.failure == LoginFailureReason.MOUNT_FAILED


def test_valid_local_key_never_asks_for_password():
    """The single most important product rule (spec section 1)."""
    password_calls = []

    def password_fn(record, mp, pw):
        password_calls.append(pw)
        return SecretBytes(b"should-not-be-called")

    flow = _flow(password=password_fn)
    outcome = attempt_automatic_login(flow)

    assert outcome.state == LoginState.MANAGER
    assert outcome.used_local_key is True
    assert outcome.fallback_used is False
    assert outcome.vms is not None
    assert outcome.vms.to_bytes() == b"V" * 32
    assert password_calls == []  # password function was never invoked


def test_missing_local_key_falls_back_to_ask_password_exactly_once():
    def local_key_fn(record, mp):
        raise Exception("no local key enrolled")

    flow = _flow(local_key=local_key_fn)
    outcome = attempt_automatic_login(flow)

    assert outcome.state == LoginState.ASK_PASSWORD
    assert outcome.fallback_used is True
    assert outcome.vms is None


def test_revoked_or_corrupt_local_key_also_falls_back():
    for exc_type in (RuntimeError, ValueError, KeyError):
        def local_key_fn(record, mp, _exc=exc_type):
            raise _exc("simulated failure")

        flow = _flow(local_key=local_key_fn)
        outcome = attempt_automatic_login(flow)
        assert outcome.state == LoginState.ASK_PASSWORD


def _no_local_key_enrolled(record, mp):
    raise Exception("no local key enrolled")


def test_submit_password_success_reaches_manager():
    flow = _flow(local_key=_no_local_key_enrolled)
    outcome = attempt_automatic_login(flow)
    assert outcome.state == LoginState.ASK_PASSWORD

    final = flow.submit_password(outcome.vault_record, outcome.mountpoint, SecretBytes("correct-password"))
    assert final.state == LoginState.MANAGER
    assert final.fallback_used is True
    assert final.vms.to_bytes() == b"V" * 32


def test_submit_password_wrong_password_stays_at_ask_password():
    def password_fn(record, mp, pw):
        raise Exception("incorrect password")

    flow = _flow(local_key=_no_local_key_enrolled, password=password_fn)
    outcome = attempt_automatic_login(flow)
    result = flow.submit_password(outcome.vault_record, outcome.mountpoint, SecretBytes("wrong"))

    assert result.state == LoginState.ASK_PASSWORD
    assert result.failure == LoginFailureReason.INCORRECT_PASSWORD


def test_submit_password_unreadable_vault_is_not_reported_as_wrong_password():
    """Regression test for a real, live bug: entering the genuinely
    correct master password produced "Incorrect password" because the
    key slot could not even be read (a permissions problem -- see
    test_device_registry.py's matching test at the lower layer, and
    core.devices.registry.VaultUnreadableError's docstring). The
    password was never actually compared, so this must surface as a
    distinct failure reason, never LoginFailureReason.INCORRECT_PASSWORD."""

    def password_fn(record, mp, pw):
        raise VaultUnreadableError("permission denied reading the password slot")

    flow = _flow(local_key=_no_local_key_enrolled, password=password_fn)
    outcome = attempt_automatic_login(flow)
    result = flow.submit_password(outcome.vault_record, outcome.mountpoint, SecretBytes("this-is-the-correct-password"))

    assert result.state == LoginState.ASK_PASSWORD
    assert result.failure == LoginFailureReason.VAULT_UNREADABLE
    assert result.failure != LoginFailureReason.INCORRECT_PASSWORD


def test_retrying_a_wrong_password_never_re_attempts_local_key():
    """Structural proof against a login loop: once fallen back to
    ASK_PASSWORD, nothing in the flow can re-enter the Local Key path
    for this same attempt."""
    local_key_calls = []

    def local_key_fn(record, mp):
        local_key_calls.append(1)
        raise Exception("no key")

    flow = _flow(local_key=local_key_fn)
    attempt_automatic_login(flow)
    assert len(local_key_calls) == 1

    # Multiple wrong-password retries...
    for _ in range(3):
        flow.submit_password(RECORD, "/media/usb", SecretBytes("still-wrong"))

    # ...must never call the local-key function again.
    assert len(local_key_calls) == 1


def test_successful_password_after_retries_still_reaches_manager():
    attempts = {"count": 0}

    def password_fn(record, mp, pw):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise Exception("wrong")
        return SecretBytes(b"V" * 32)

    flow = _flow(local_key=_no_local_key_enrolled, password=password_fn)
    attempt_automatic_login(flow)

    flow.submit_password(RECORD, "/media/usb", SecretBytes("wrong-1"))
    flow.submit_password(RECORD, "/media/usb", SecretBytes("wrong-2"))
    final = flow.submit_password(RECORD, "/media/usb", SecretBytes("correct"))

    assert final.state == LoginState.MANAGER
    assert final.vms.to_bytes() == b"V" * 32
