"""First-time setup state machine (spec section 26).

::

    FIRST_RUN -> USB_SELECTION -> [ADOPT_OR_CREATE] -> PASSWORD_CREATION
              -> LOCAL_KEY_OPTIONAL -> VAULT_CREATION -> DEVICE_REGISTRATION
              -> HOTKEY_SETUP -> USB_REMOVAL_CONFIGURATION -> SETUP_COMPLETE

``ADOPT_OR_CREATE`` is the one optional branch: it is only reached
when the selected USB already has a non-ASH KDBX on it (spec section
13's user-approved "offer to adopt inline" flow); a fresh USB skips
straight from ``USB_SELECTION`` to ``PASSWORD_CREATION``.

This class enforces forward-only, in-order progression and collects
every wizard answer into one ``SetupDraft`` that is only turned into
real, on-disk vault state at the ``VAULT_CREATION`` step, via
``core.vault.provisioning.create_new_vault``/``adopt_existing_vault`` --
both already atomic on their own (temp-directory-then-rename, or
backup-then-rollback). This module's own job is purely sequencing and
holding not-yet-committed answers; it never itself writes to disk, and
a cancel or failure at any point before ``VAULT_CREATION`` leaves
exactly zero on-disk trace (spec: "do not create a partially
initialized account silently").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SetupState(str, Enum):
    FIRST_RUN = "first_run"
    USB_SELECTION = "usb_selection"
    ADOPT_OR_CREATE = "adopt_or_create"
    PASSWORD_CREATION = "password_creation"
    LOCAL_KEY_OPTIONAL = "local_key_optional"
    VAULT_CREATION = "vault_creation"
    DEVICE_REGISTRATION = "device_registration"
    HOTKEY_SETUP = "hotkey_setup"
    USB_REMOVAL_CONFIGURATION = "usb_removal_configuration"
    SETUP_COMPLETE = "setup_complete"
    FAILED = "failed"


_TRANSITIONS: dict[SetupState, tuple[SetupState, ...]] = {
    SetupState.FIRST_RUN: (SetupState.USB_SELECTION,),
    SetupState.USB_SELECTION: (SetupState.ADOPT_OR_CREATE, SetupState.PASSWORD_CREATION),
    SetupState.ADOPT_OR_CREATE: (SetupState.PASSWORD_CREATION,),
    SetupState.PASSWORD_CREATION: (SetupState.LOCAL_KEY_OPTIONAL,),
    SetupState.LOCAL_KEY_OPTIONAL: (SetupState.VAULT_CREATION,),
    SetupState.VAULT_CREATION: (SetupState.DEVICE_REGISTRATION,),
    SetupState.DEVICE_REGISTRATION: (SetupState.HOTKEY_SETUP,),
    SetupState.HOTKEY_SETUP: (SetupState.USB_REMOVAL_CONFIGURATION,),
    SetupState.USB_REMOVAL_CONFIGURATION: (SetupState.SETUP_COMPLETE,),
    SetupState.SETUP_COMPLETE: (),
    SetupState.FAILED: (),
}

# Any state before the vault actually exists on disk can abort
# cleanly with zero trace; once VAULT_CREATION has run, a "cancel"
# from the UI must instead go through explicit vault removal, not
# this flow's `fail()`.
_ABORTABLE_STATES = (
    SetupState.FIRST_RUN,
    SetupState.USB_SELECTION,
    SetupState.ADOPT_OR_CREATE,
    SetupState.PASSWORD_CREATION,
    SetupState.LOCAL_KEY_OPTIONAL,
)


class InvalidTransitionError(Exception):
    pass


@dataclass
class SetupDraft:
    """Everything collected across the wizard so far. Nothing here
    touches disk until ``VAULT_CREATION``."""

    mountpoint: str | None = None
    container_rel_path: str = "ASH"
    vault_name: str = "My Passwords"
    is_adoption: bool = False
    existing_keyfile_rel_path: str | None = None
    enroll_local_key: bool = True
    device_label: str | None = None
    hotkey_accelerator: str | None = None
    hotkey_backend: str | None = None
    usb_removal_action: str = "lock_immediately"
    agent_autostart_enabled: bool = True


@dataclass
class SetupFlow:
    state: SetupState = SetupState.FIRST_RUN
    draft: SetupDraft = field(default_factory=SetupDraft)
    failure_reason: str | None = None

    def can_advance_to(self, target: SetupState) -> bool:
        if target is SetupState.FAILED:
            return self.state in _ABORTABLE_STATES
        return target in _TRANSITIONS.get(self.state, ())

    def advance_to(self, target: SetupState) -> None:
        if not self.can_advance_to(target):
            raise InvalidTransitionError(f"Cannot advance from {self.state.value} to {target.value}")
        self.state = target

    def fail(self, reason: str) -> None:
        if self.state not in _ABORTABLE_STATES:
            raise InvalidTransitionError(
                f"Cannot abort from {self.state.value} -- the vault already exists on disk; "
                "use explicit vault removal instead of the setup flow."
            )
        self.state = SetupState.FAILED
        self.failure_reason = reason

    def is_complete(self) -> bool:
        return self.state is SetupState.SETUP_COMPLETE
