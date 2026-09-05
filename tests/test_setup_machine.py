"""Tests for core.flows.setup_machine -- spec section 26's first-run
setup sequencing, and the "never a partially initialized account"
guarantee."""

from __future__ import annotations

import pytest

from passman.core.flows.setup_machine import InvalidTransitionError, SetupFlow, SetupState


def test_initial_state_is_first_run():
    flow = SetupFlow()
    assert flow.state == SetupState.FIRST_RUN


def test_full_happy_path_fresh_usb_skips_adopt_or_create():
    flow = SetupFlow()
    order = [
        SetupState.USB_SELECTION,
        SetupState.PASSWORD_CREATION,  # ADOPT_OR_CREATE skipped -- fresh USB
        SetupState.LOCAL_KEY_OPTIONAL,
        SetupState.VAULT_CREATION,
        SetupState.DEVICE_REGISTRATION,
        SetupState.HOTKEY_SETUP,
        SetupState.USB_REMOVAL_CONFIGURATION,
        SetupState.SETUP_COMPLETE,
    ]
    for target in order:
        flow.advance_to(target)
    assert flow.is_complete()


def test_full_happy_path_with_adoption_branch():
    flow = SetupFlow()
    flow.advance_to(SetupState.USB_SELECTION)
    flow.advance_to(SetupState.ADOPT_OR_CREATE)
    flow.advance_to(SetupState.PASSWORD_CREATION)
    flow.advance_to(SetupState.LOCAL_KEY_OPTIONAL)
    flow.advance_to(SetupState.VAULT_CREATION)
    flow.advance_to(SetupState.DEVICE_REGISTRATION)
    flow.advance_to(SetupState.HOTKEY_SETUP)
    flow.advance_to(SetupState.USB_REMOVAL_CONFIGURATION)
    flow.advance_to(SetupState.SETUP_COMPLETE)
    assert flow.is_complete()


def test_cannot_skip_states():
    flow = SetupFlow()
    with pytest.raises(InvalidTransitionError):
        flow.advance_to(SetupState.PASSWORD_CREATION)  # skipping USB_SELECTION


def test_cannot_go_backwards():
    flow = SetupFlow()
    flow.advance_to(SetupState.USB_SELECTION)
    flow.advance_to(SetupState.PASSWORD_CREATION)
    with pytest.raises(InvalidTransitionError):
        flow.advance_to(SetupState.USB_SELECTION)


def test_cannot_advance_past_setup_complete():
    flow = SetupFlow()
    for target in (
        SetupState.USB_SELECTION,
        SetupState.PASSWORD_CREATION,
        SetupState.LOCAL_KEY_OPTIONAL,
        SetupState.VAULT_CREATION,
        SetupState.DEVICE_REGISTRATION,
        SetupState.HOTKEY_SETUP,
        SetupState.USB_REMOVAL_CONFIGURATION,
        SetupState.SETUP_COMPLETE,
    ):
        flow.advance_to(target)
    with pytest.raises(InvalidTransitionError):
        flow.advance_to(SetupState.HOTKEY_SETUP)


def test_can_abort_before_vault_creation():
    flow = SetupFlow()
    flow.advance_to(SetupState.USB_SELECTION)
    flow.advance_to(SetupState.PASSWORD_CREATION)
    flow.fail("user cancelled")
    assert flow.state == SetupState.FAILED
    assert flow.failure_reason == "user cancelled"


def test_cannot_abort_via_fail_after_vault_creation():
    """Once the vault exists on disk, cancelling the wizard must not
    silently discard it -- that has to go through explicit vault
    removal, never this flow's fail()."""
    flow = SetupFlow()
    flow.advance_to(SetupState.USB_SELECTION)
    flow.advance_to(SetupState.PASSWORD_CREATION)
    flow.advance_to(SetupState.LOCAL_KEY_OPTIONAL)
    flow.advance_to(SetupState.VAULT_CREATION)
    with pytest.raises(InvalidTransitionError):
        flow.fail("changed my mind")


def test_draft_defaults_are_safe():
    from passman.core.flows.setup_machine import SetupDraft

    draft = SetupDraft()
    assert draft.enroll_local_key is True
    assert draft.usb_removal_action == "lock_immediately"
    assert draft.is_adoption is False
    assert draft.mountpoint is None
