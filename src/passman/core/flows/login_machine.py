"""Returning-user login state machine (spec section 27).

::

    USB_DETECTED -> IDENTIFY_USB -> CHECK_LOCAL_KEY
                       |-- valid -----> UNLOCK_WITH_LOCAL_KEY --+
                       `-- otherwise -> ASK_PASSWORD -----------+--> OPEN_VAULT -> MANAGER

The "app not installed" branch (spec section 18) is handled entirely
outside a running process (a udev rule + the ``installer`` package),
so it has no state here -- by the time this module runs, the
application is, by definition, already installed and running.

This module is the *decision* logic only: every actual I/O operation
(USB enumeration, mounting, unlocking) is injected as a callable, so
the whole flow is unit-testable without a display, a real USB, or a
real vault -- following this project's existing pattern (see
``core.auth.engine.LoginEngine``'s injected ``backend``/``sleep_fn``).

The critical product guarantee lives in ``attempt_automatic_login``:
the password is *never* requested unless a Local Key attempt has
already concluded (successfully skipped, or genuinely failed) --
there is no code path that asks for the password first, and none that
retries the Local Key after falling back to it (so a login can never
loop).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from ..security.memory import SecretBytes
from ..vaults.registry import VaultRecord


class LoginState(str, Enum):
    USB_DETECTED = "usb_detected"
    IDENTIFY_USB = "identify_usb"
    CHECK_LOCAL_KEY = "check_local_key"
    ASK_PASSWORD = "ask_password"
    MANAGER = "manager"
    FAILED = "failed"


class LoginFailureReason(str, Enum):
    NO_MATCHING_USB = "no_matching_usb"
    MOUNT_FAILED = "mount_failed"
    INCORRECT_PASSWORD = "incorrect_password"
    VAULT_OPEN_FAILED = "vault_open_failed"


@dataclass
class LoginOutcome:
    state: LoginState
    vault_record: VaultRecord | None = None
    mountpoint: str | None = None
    used_local_key: bool = False
    fallback_used: bool = False
    failure: LoginFailureReason | None = None
    detail: str = ""
    # Populated only when state is MANAGER. The caller must consume
    # (derive the KDBX password from it and open the vault) and then
    # wipe it immediately -- this is the one hop where the raw Vault
    # Master Secret exists outside core.crypto/core.devices, and only
    # because the in-process login controller is the trusted caller,
    # never a log or serialization boundary.
    vms: SecretBytes | None = None


IdentifyUsbFn = Callable[[], "VaultRecord | None"]
MountFn = Callable[["VaultRecord"], "str | None"]
UnlockWithLocalKeyFn = Callable[["VaultRecord", str], SecretBytes]
UnlockWithPasswordFn = Callable[["VaultRecord", str, SecretBytes], SecretBytes]


@dataclass
class LoginFlow:
    """One login attempt for one USB-insertion event.

    ``identify_usb`` must return the single matching, registered
    ``VaultRecord`` for whatever is currently connected, or ``None`` --
    the caller is responsible for the actual UDisks2 enumeration and
    identity matching (``integration.usb`` + ``core.vaults.registry``).
    ``unlock_with_local_key``/``unlock_with_password`` must raise on
    any failure (they are expected to be thin wrappers around
    ``core.devices.registry.unlock_with_local_key``/
    ``unlock_with_password``) -- this class only decides what to do
    with success vs. failure, never inspects the exception type.
    """

    identify_usb: IdentifyUsbFn
    mount: MountFn
    unlock_with_local_key: UnlockWithLocalKeyFn
    unlock_with_password: UnlockWithPasswordFn

    _fallback_used: bool = field(default=False, init=False)

    def identify(self) -> LoginOutcome:
        record = self.identify_usb()
        if record is None:
            return LoginOutcome(state=LoginState.FAILED, failure=LoginFailureReason.NO_MATCHING_USB)
        mountpoint = self.mount(record)
        if mountpoint is None:
            return LoginOutcome(
                state=LoginState.FAILED, vault_record=record, failure=LoginFailureReason.MOUNT_FAILED
            )
        return LoginOutcome(state=LoginState.CHECK_LOCAL_KEY, vault_record=record, mountpoint=mountpoint)

    def try_local_key(self, record: VaultRecord, mountpoint: str) -> LoginOutcome:
        """Exactly one attempt. ANY failure (missing, corrupt, revoked,
        wrong device binding, Secret Service gone -- deliberately not
        distinguished here, see spec section 21) falls through to
        ASK_PASSWORD. This method is never called again for the same
        login attempt once it has run once."""
        try:
            vms = self.unlock_with_local_key(record, mountpoint)
        except Exception:  # noqa: BLE001 - any failure at all means "fall back to password", by design
            self._fallback_used = True
            return LoginOutcome(
                state=LoginState.ASK_PASSWORD, vault_record=record, mountpoint=mountpoint, fallback_used=True
            )
        return LoginOutcome(
            state=LoginState.MANAGER,
            vault_record=record,
            mountpoint=mountpoint,
            used_local_key=True,
            vms=vms,
        )

    def submit_password(self, record: VaultRecord, mountpoint: str, password: SecretBytes) -> LoginOutcome:
        """May be called repeatedly (the user can retype a wrong
        password) -- it never re-attempts the Local Key, so there is
        no path back into ``try_local_key`` for this attempt."""
        try:
            vms = self.unlock_with_password(record, mountpoint, password)
        except Exception:  # noqa: BLE001 - wrong password or a broken slot; both surface identically to the user
            return LoginOutcome(
                state=LoginState.ASK_PASSWORD,
                vault_record=record,
                mountpoint=mountpoint,
                fallback_used=self._fallback_used,
                failure=LoginFailureReason.INCORRECT_PASSWORD,
            )
        return LoginOutcome(
            state=LoginState.MANAGER,
            vault_record=record,
            mountpoint=mountpoint,
            fallback_used=self._fallback_used,
            vms=vms,
        )


def attempt_automatic_login(flow: LoginFlow) -> LoginOutcome:
    """The whole non-interactive portion of spec section 27: identify
    the USB, mount it, and try the Local Key -- all without ever
    prompting the user. Returns:

      * ``MANAGER``      -- Local Key succeeded; ``.vms`` is populated
                             and ready to open the vault. The password
                             was never requested.
      * ``ASK_PASSWORD`` -- USB identified and mounted, but the Local
                             Key is unavailable or invalid; the caller
                             must now prompt for the master password.
      * ``FAILED``        -- no matching USB, or it could not be
                             mounted.
    """
    outcome = flow.identify()
    if outcome.state != LoginState.CHECK_LOCAL_KEY:
        return outcome
    return flow.try_local_key(outcome.vault_record, outcome.mountpoint)
