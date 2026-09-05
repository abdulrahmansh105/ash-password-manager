"""Integration-level tests for PasswordManagerApp._check_usb_still_present
itself (spec sections 8, 10, 33, 34) -- not just the pure
should_lock_for_usb_removal function it delegates to (see
test_usb_identity.py for that), but the actual method, including its
UdisksError fail-closed branch and its behavior against a genuinely
non-LUKS (plain filesystem) vault.

Uses a minimal duck-typed stand-in for `self` rather than constructing
a real GTK Adw.Application -- _check_usb_still_present only ever reads
`.registration`, `.mountpoint`, `.session`, and `.settings` off it, and
`core.security.session.Session` has no GTK dependency at all, so this
exercises the real method body with no display required. Matches this
project's existing hand-rolled-fakes idiom.
"""

from __future__ import annotations

from dataclasses import dataclass

from passman.config.store import Settings
from passman.core.security.session import LockReason, Session
from passman.core.vaults.registry import VaultRecord
from passman.integration.usb.udisks import UdisksError
from passman.ui.app import PasswordManagerApp


class _FakeVault:
    def close(self) -> None:
        pass


@dataclass
class _FakeApp:
    registration: object
    mountpoint: str
    settings: Settings
    session: Session


def _unlocked_app(*, registration, mountpoint="/run/media/ash/vault", usb_removal_action="lock_immediately", lock_on_usb_removal=True):
    settings = Settings()
    settings.usb_removal_action = usb_removal_action
    settings.lock_on_usb_removal = lock_on_usb_removal
    session = Session(inactivity_timeout_seconds=0)
    session.unlock(_FakeVault())
    app = _FakeApp(registration=registration, mountpoint=mountpoint, settings=settings, session=session)
    return app


def test_udisks_error_locks_regardless_of_usb_removal_action(monkeypatch):
    """Fail-closed: an inability to even determine USB status is a
    different, rarer condition than a confirmed removal, and must
    never be silently treated as "keep unlocked" just because that is
    the user's removal policy -- that policy is about a *confirmed*
    removal, not about losing the ability to check at all."""

    def raise_udisks_error():
        raise UdisksError("simulated: udisksctl/lsblk unavailable")

    monkeypatch.setattr("passman.ui.app.list_block_devices", raise_udisks_error)

    for action in ("lock_immediately", "keep_unlocked"):
        record = VaultRecord(vault_id="v1", name="Test", filesystem_uuid="fs-1", luks_uuid=None)
        app = _unlocked_app(registration=record, usb_removal_action=action)
        assert app.session.is_unlocked()

        PasswordManagerApp._check_usb_still_present(app)

        assert not app.session.is_unlocked(), f"UdisksError must fail-closed even with usb_removal_action={action!r}"


def test_non_luks_vault_genuinely_mounted_does_not_spuriously_lock(monkeypatch):
    """The actual bug: a plain-filesystem vault (luks_uuid=None) that
    is genuinely connected and mounted at the expected path must not
    be locked, exercised through the real method + real
    evaluate_usb_status/should_lock_for_usb_removal chain, not just
    the pure function in isolation."""
    from passman.integration.usb.identity import BlockDevice

    mountpoint = "/run/media/ash/vault"

    def fake_list_block_devices():
        return [BlockDevice(name="sdb1", path="/dev/sdb1", uuid="fs-1", fstype="ext4", type="part", mountpoint=mountpoint)]

    monkeypatch.setattr("passman.ui.app.list_block_devices", fake_list_block_devices)

    record = VaultRecord(vault_id="v1", name="Test", filesystem_uuid="fs-1", luks_uuid=None)
    app = _unlocked_app(registration=record, mountpoint=mountpoint, usb_removal_action="lock_immediately")

    PasswordManagerApp._check_usb_still_present(app)

    assert app.session.is_unlocked(), "a genuinely connected, correctly-mounted non-LUKS vault must not self-lock"


def test_non_luks_vault_removed_locks_under_lock_immediately(monkeypatch):
    monkeypatch.setattr("passman.ui.app.list_block_devices", lambda: [])  # nothing connected at all

    record = VaultRecord(vault_id="v1", name="Test", filesystem_uuid="fs-1", luks_uuid=None)
    app = _unlocked_app(registration=record, usb_removal_action="lock_immediately")

    PasswordManagerApp._check_usb_still_present(app)

    assert not app.session.is_unlocked()


def test_non_luks_vault_removed_does_not_lock_under_keep_unlocked(monkeypatch):
    monkeypatch.setattr("passman.ui.app.list_block_devices", lambda: [])

    record = VaultRecord(vault_id="v1", name="Test", filesystem_uuid="fs-1", luks_uuid=None)
    app = _unlocked_app(registration=record, usb_removal_action="keep_unlocked")

    PasswordManagerApp._check_usb_still_present(app)

    assert app.session.is_unlocked()
