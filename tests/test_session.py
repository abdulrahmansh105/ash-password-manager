"""Session lock-trigger tests (spec section 6/33/34): every trigger goes
through the same lock() path, which must close the vault, clear the
clipboard, and notify subscribers -- and USB removal / inactivity /
manual close / a vault error must all reach it."""

from __future__ import annotations

from passman.core.security.session import LockReason, Session, SessionState


class FakeVault:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeClipboard:
    def __init__(self) -> None:
        self.cleared = False

    def clear_now(self) -> None:
        self.cleared = True


def _session() -> tuple[Session, FakeVault, FakeClipboard]:
    clipboard = FakeClipboard()
    session = Session(inactivity_timeout_seconds=60, _clipboard=clipboard)
    vault = FakeVault()
    return session, vault, clipboard


def test_unlock_sets_state_and_vault():
    session, vault, _ = _session()
    session.unlock(vault)
    assert session.state == SessionState.UNLOCKED
    assert session.vault() is vault


def test_lock_closes_vault():
    session, vault, _ = _session()
    session.unlock(vault)
    session.lock(LockReason.MANUAL_CLOSE)
    assert vault.closed is True
    assert session.state == SessionState.LOCKED


def test_lock_clears_clipboard():
    session, vault, clipboard = _session()
    session.unlock(vault)
    session.lock(LockReason.USB_REMOVED)
    assert clipboard.cleared is True


def test_lock_invokes_callback_with_reason():
    session, vault, _ = _session()
    seen = []
    session.set_on_lock(lambda reason: seen.append(reason))
    session.unlock(vault)
    session.lock(LockReason.SCREEN_LOCKED)
    assert seen == [LockReason.SCREEN_LOCKED]


def test_vault_accessor_raises_when_locked():
    session, _, _ = _session()
    try:
        session.vault()
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass


def test_double_lock_is_a_noop():
    session, vault, _ = _session()
    session.unlock(vault)
    session.lock(LockReason.MANUAL_CLOSE)
    session.lock(LockReason.MANUAL_CLOSE)  # must not raise or double-callback
    assert session.state == SessionState.LOCKED


def test_inactivity_timeout_locks_after_elapsed():
    session, vault, _ = _session()
    session.inactivity_timeout_seconds = 10
    session.unlock(vault)
    session.touch_activity(now=1000.0)
    locked = session.check_inactivity(now=1011.0)
    assert locked is True
    assert session.state == SessionState.LOCKED


def test_inactivity_timeout_does_not_lock_before_elapsed():
    session, vault, _ = _session()
    session.inactivity_timeout_seconds = 10
    session.unlock(vault)
    session.touch_activity(now=1000.0)
    locked = session.check_inactivity(now=1005.0)
    assert locked is False
    assert session.state == SessionState.UNLOCKED


def test_zero_timeout_disables_inactivity_lock():
    session, vault, _ = _session()
    session.inactivity_timeout_seconds = 0
    session.unlock(vault)
    session.touch_activity(now=1000.0)
    locked = session.check_inactivity(now=999_999.0)
    assert locked is False


def test_usb_removal_reason_reaches_callback():
    session, vault, _ = _session()
    seen = []
    session.set_on_lock(lambda reason: seen.append(reason))
    session.unlock(vault)
    session.lock(LockReason.USB_REMOVED)
    assert seen == [LockReason.USB_REMOVED]
