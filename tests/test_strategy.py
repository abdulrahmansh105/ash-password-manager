from __future__ import annotations

from passman.core.auth.strategy import DEFAULT_STRATEGY, AuthStep, AuthStrategy, StepAction


def test_default_strategy_round_trips_through_json():
    raw = DEFAULT_STRATEGY.to_json()
    restored = AuthStrategy.from_json(raw)
    assert restored.name == DEFAULT_STRATEGY.name
    assert len(restored.steps) == len(DEFAULT_STRATEGY.steps)
    assert restored.steps[0].action == StepAction.TYPE_USERNAME


def test_from_json_none_returns_default():
    assert AuthStrategy.from_json(None) is DEFAULT_STRATEGY


def test_from_json_garbage_returns_default():
    assert AuthStrategy.from_json("not json").name == "default"
    assert AuthStrategy.from_json("{}").name == "default"


def test_custom_strategy_round_trip():
    custom = AuthStrategy(
        name="custom",
        steps=(
            AuthStep(action=StepAction.TYPE_PASSWORD),
            AuthStep(action=StepAction.WAIT, value="500"),
            AuthStep(action=StepAction.KEY_COMBO, value="ctrl+enter"),
        ),
    )
    restored = AuthStrategy.from_json(custom.to_json())
    assert restored.name == "custom"
    assert restored.steps[2].value == "ctrl+enter"


def test_strategy_json_never_contains_secret_placeholder_text():
    # Strategies describe *actions*, never values -- there is no field
    # on AuthStep that could hold a literal secret.
    raw = DEFAULT_STRATEGY.to_json()
    assert "password" not in raw.lower() or "type_password" in raw.lower()
