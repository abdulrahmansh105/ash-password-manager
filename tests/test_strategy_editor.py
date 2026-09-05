"""Tests for the pure Auto-Type strategy editor model
(core/auth/strategy_editor.py) -- add/remove/duplicate/reorder/update,
validation, preview text, and the `enabled` field's serialization/
backward-compatibility. No GTK involved; no vault touched."""

from __future__ import annotations

from passman.core.auth.strategy import (
    DEFAULT_STRATEGY,
    MULTI_PAGE_STRATEGY,
    AuthStep,
    AuthStrategy,
    StepAction,
)
from passman.core.auth.strategy_editor import (
    MAX_WAIT_MS,
    MIN_WAIT_MS,
    add_step,
    duplicate_step,
    is_valid,
    matches_preset,
    move_step,
    preview_text,
    remove_step,
    toggle_enabled,
    update_step,
    validate_key_combo,
    validate_strategy,
    validate_wait_ms,
)


def _steps():
    return (
        AuthStep(action=StepAction.TYPE_USERNAME),
        AuthStep(action=StepAction.KEY_TAB),
        AuthStep(action=StepAction.TYPE_PASSWORD),
    )


# -- enabled field: serialization + backward compatibility -----------------


def test_auth_step_enabled_defaults_true():
    step = AuthStep(action=StepAction.KEY_TAB)
    assert step.enabled is True


def test_auth_step_to_dict_includes_enabled():
    step = AuthStep(action=StepAction.KEY_TAB, enabled=False)
    d = step.to_dict()
    assert d["enabled"] is False


def test_auth_step_from_dict_without_enabled_key_defaults_true():
    # Simulates a strategy JSON written before this field existed.
    d = {"action": "key_tab"}
    step = AuthStep.from_dict(d)
    assert step.enabled is True


def test_strategy_round_trip_preserves_disabled_steps():
    strategy = AuthStrategy(
        name="custom",
        steps=(
            AuthStep(action=StepAction.TYPE_USERNAME, enabled=True),
            AuthStep(action=StepAction.KEY_TAB, enabled=False),
        ),
    )
    restored = AuthStrategy.from_json(strategy.to_json())
    assert restored.steps[0].enabled is True
    assert restored.steps[1].enabled is False


# -- add / remove / duplicate / move / update / toggle ----------------------


def test_add_step_appends_by_default():
    steps = add_step((), AuthStep(action=StepAction.KEY_ENTER))
    assert len(steps) == 1
    assert steps[0].action == StepAction.KEY_ENTER


def test_add_step_at_specific_index():
    base = _steps()
    steps = add_step(base, AuthStep(action=StepAction.WAIT, value="500"), index=1)
    assert steps[1].action == StepAction.WAIT
    assert len(steps) == 4


def test_remove_step():
    base = _steps()
    steps = remove_step(base, 1)
    assert len(steps) == 2
    assert steps[0].action == StepAction.TYPE_USERNAME
    assert steps[1].action == StepAction.TYPE_PASSWORD


def test_remove_step_out_of_range_is_noop():
    base = _steps()
    assert remove_step(base, 99) == base


def test_duplicate_step():
    base = _steps()
    steps = duplicate_step(base, 0)
    assert len(steps) == 4
    assert steps[0].action == steps[1].action == StepAction.TYPE_USERNAME


def test_move_step_up_and_down():
    base = _steps()
    moved_down = move_step(base, 0, 1)
    assert moved_down[0].action == StepAction.KEY_TAB
    assert moved_down[1].action == StepAction.TYPE_USERNAME

    moved_up = move_step(base, 2, -1)
    assert moved_up[1].action == StepAction.TYPE_PASSWORD
    assert moved_up[2].action == StepAction.KEY_TAB


def test_move_step_out_of_bounds_is_noop():
    base = _steps()
    assert move_step(base, 0, -1) == base  # already first
    assert move_step(base, len(base) - 1, 1) == base  # already last


def test_update_step_changes_value():
    base = (AuthStep(action=StepAction.WAIT, value="500"),)
    steps = update_step(base, 0, value="1000")
    assert steps[0].value == "1000"


def test_update_step_out_of_range_is_noop():
    base = _steps()
    assert update_step(base, 99, value="x") == base


def test_toggle_enabled():
    base = (AuthStep(action=StepAction.KEY_TAB, enabled=True),)
    steps = toggle_enabled(base, 0)
    assert steps[0].enabled is False
    steps = toggle_enabled(steps, 0)
    assert steps[0].enabled is True


def test_editing_operations_never_mutate_input_tuple():
    base = _steps()
    _ = remove_step(base, 0)
    _ = add_step(base, AuthStep(action=StepAction.KEY_ENTER))
    _ = duplicate_step(base, 0)
    assert base == _steps()  # unchanged -- everything is pure/immutable


# -- validators ---------------------------------------------------------------


def test_validate_key_combo_accepts_well_formed():
    assert validate_key_combo("ctrl+v") is True
    assert validate_key_combo("ctrl+shift+a") is True


def test_validate_key_combo_rejects_no_modifier():
    assert validate_key_combo("a+b") is False


def test_validate_key_combo_rejects_empty():
    assert validate_key_combo("") is False


def test_validate_key_combo_rejects_shell_metacharacters():
    for bad in ["ctrl+v; rm -rf ~", "ctrl+`whoami`", "ctrl+v|cat", "ctrl+v && ls", "ctrl + v"]:
        assert validate_key_combo(bad) is False, bad


def test_validate_key_combo_rejects_uppercase():
    assert validate_key_combo("Ctrl+V") is False


def test_validate_wait_ms_bounds():
    assert validate_wait_ms(str(MIN_WAIT_MS)) is True
    assert validate_wait_ms(str(MAX_WAIT_MS)) is True
    assert validate_wait_ms(str(MAX_WAIT_MS + 1)) is False
    assert validate_wait_ms("-1") is False
    assert validate_wait_ms("not a number") is False
    assert validate_wait_ms("") is False


# -- preview text --------------------------------------------------------------


def test_preview_text_matches_expected_arrow_format():
    text = preview_text(DEFAULT_STRATEGY.steps)
    assert text == "Type Username -> Tab -> Type Password -> Enter -> Wait 1500ms -> Type TOTP -> Enter"


def test_preview_text_empty_strategy():
    assert "empty" in preview_text(()).lower()


def test_preview_text_shows_disabled_steps_bracketed():
    steps = (AuthStep(action=StepAction.KEY_TAB, enabled=False),)
    assert preview_text(steps) == "[Tab]"


def test_preview_text_shows_key_combo_value():
    steps = (AuthStep(action=StepAction.KEY_COMBO, value="ctrl+v"),)
    assert "ctrl+v" in preview_text(steps)


# -- validate_strategy: full validation rules --------------------------------


def test_valid_default_strategy_has_no_problems():
    problems = validate_strategy(DEFAULT_STRATEGY.steps, account_has_totp=True)
    assert problems == []


def test_empty_strategy_requires_at_least_one_input_step():
    problems = validate_strategy((), account_has_totp=True)
    assert any("at least one input step" in p.lower() for p in problems)


def test_only_navigation_steps_is_invalid():
    steps = (AuthStep(action=StepAction.KEY_TAB), AuthStep(action=StepAction.KEY_ENTER))
    problems = validate_strategy(steps, account_has_totp=True)
    assert any("input step" in p.lower() for p in problems)


def test_totp_step_invalid_when_account_has_no_totp():
    steps = (AuthStep(action=StepAction.TYPE_PASSWORD), AuthStep(action=StepAction.TYPE_TOTP))
    problems = validate_strategy(steps, account_has_totp=False)
    assert any("totp" in p.lower() for p in problems)
    assert is_valid(steps, account_has_totp=False) is False


def test_totp_step_valid_when_account_has_totp():
    steps = (AuthStep(action=StepAction.TYPE_PASSWORD), AuthStep(action=StepAction.TYPE_TOTP))
    assert is_valid(steps, account_has_totp=True) is True


def test_disabled_totp_step_does_not_trigger_totp_requirement():
    steps = (
        AuthStep(action=StepAction.TYPE_PASSWORD),
        AuthStep(action=StepAction.TYPE_TOTP, enabled=False),
    )
    # Disabled TOTP step on a no-TOTP account must not block saving --
    # it will never actually execute.
    problems = validate_strategy(steps, account_has_totp=False)
    assert not any("totp" in p.lower() for p in problems)


def test_username_step_invalid_when_account_has_no_username():
    steps = (AuthStep(action=StepAction.TYPE_USERNAME), AuthStep(action=StepAction.TYPE_PASSWORD))
    problems = validate_strategy(steps, account_has_totp=False, account_has_username=False)
    assert any("username" in p.lower() for p in problems)


def test_password_step_invalid_when_account_has_no_password():
    steps = (AuthStep(action=StepAction.TYPE_PASSWORD),)
    problems = validate_strategy(steps, account_has_totp=False, account_has_password=False)
    assert any("password" in p.lower() for p in problems)


def test_invalid_wait_value_reported_with_step_number():
    steps = (AuthStep(action=StepAction.TYPE_PASSWORD), AuthStep(action=StepAction.WAIT, value="not-a-number"))
    problems = validate_strategy(steps, account_has_totp=False)
    assert any(p.startswith("Step 2") for p in problems)


def test_invalid_key_combo_reported():
    steps = (AuthStep(action=StepAction.TYPE_PASSWORD), AuthStep(action=StepAction.KEY_COMBO, value="bad;combo"))
    problems = validate_strategy(steps, account_has_totp=False)
    assert any("key combination" in p.lower() for p in problems)


def test_validate_strategy_never_raises_on_garbage():
    garbage = (AuthStep(action=StepAction.WAIT, value=None), AuthStep(action=StepAction.KEY_COMBO, value=None))
    # Must return a list of problems, not raise.
    problems = validate_strategy(garbage, account_has_totp=True)
    assert isinstance(problems, list)
    assert len(problems) >= 2


# -- preset matching ------------------------------------------------------------


def test_matches_preset_true_for_identical_steps():
    assert matches_preset(DEFAULT_STRATEGY.steps, DEFAULT_STRATEGY) is True


def test_matches_preset_false_after_any_edit():
    edited = update_step(DEFAULT_STRATEGY.steps, 0, timeout_ms=9999)
    assert matches_preset(edited, DEFAULT_STRATEGY) is False


def test_matches_preset_false_for_different_preset():
    assert matches_preset(DEFAULT_STRATEGY.steps, MULTI_PAGE_STRATEGY) is False
