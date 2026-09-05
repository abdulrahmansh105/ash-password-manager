"""Pure, toolkit-independent editing operations + validation for
``AuthStrategy``/``AuthStep`` lists.

This is the model behind the GUI Auto-Type/Auth Strategy editor
(``ui/strategy_editor.py``) -- deliberately separated so every editor
operation (add/remove/duplicate/reorder/update/validate) is unit
testable without GTK, matching this project's existing core/ui split.
Nothing here ever touches a secret value: steps describe *actions*
(``type_password``, ...), never carry the password/TOTP/username text
itself.
"""

from __future__ import annotations

import re
from dataclasses import replace

from .strategy import AuthStep, AuthStrategy, StepAction

# Deliberately strict: modifier(s) + one final key, lowercase
# alphanumerics only, joined by "+", at most 4 parts. This can never
# contain shell metacharacters (;, |, &, $, `, >, <, spaces, quotes) --
# the value is only ever used to build a keypress event
# (input/ydotool_backend.py's _KEYCODES lookup), never passed to a
# shell, but the strict grammar is enforced anyway as defense in depth
# per the explicit "never allow arbitrary shell commands" requirement.
_COMBO_RE = re.compile(r"^[a-z0-9]+(\+[a-z0-9]+){1,3}$")
_KNOWN_MODIFIERS = {"ctrl", "shift", "alt"}

MIN_WAIT_MS = 0
MAX_WAIT_MS = 30_000  # 30s -- long enough for a slow page load, short
# enough that a mistyped value (e.g. an extra zero) doesn't hang autotype
# for minutes without the user noticing something is wrong.

# Steps that insert a secret -- used by validation to decide which
# actions require which account capability.
_SECRET_STEPS = {StepAction.TYPE_USERNAME, StepAction.TYPE_PASSWORD, StepAction.TYPE_TOTP}

STEP_LABELS: dict[StepAction, str] = {
    StepAction.TYPE_USERNAME: "Type Username",
    StepAction.TYPE_PASSWORD: "Type Password",
    StepAction.TYPE_TOTP: "Type TOTP",
    StepAction.KEY_TAB: "Tab",
    StepAction.KEY_ENTER: "Enter",
    StepAction.KEY_ESCAPE: "Escape",
    StepAction.KEY_COMBO: "Key Combination",
    StepAction.WAIT: "Wait",
    StepAction.FOCUS_FIELD: "Focus Field",
}


def validate_key_combo(value: str) -> bool:
    """True if ``value`` is a well-formed ``modifier+...+key`` combo
    (e.g. ``ctrl+v``). Rejects anything else, including empty strings,
    whitespace, shell metacharacters, or a combo with no modifier."""
    if not value:
        return False
    if not _COMBO_RE.fullmatch(value):
        return False
    parts = value.split("+")
    # At least one recognized modifier, and the combo isn't *all*
    # modifiers with no actual key to press.
    return any(p in _KNOWN_MODIFIERS for p in parts[:-1])


def validate_wait_ms(value: str) -> bool:
    """True if ``value`` parses as an integer millisecond count within
    ``[MIN_WAIT_MS, MAX_WAIT_MS]``."""
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return False
    return MIN_WAIT_MS <= ms <= MAX_WAIT_MS


# -- list editing (all pure: take a tuple, return a new tuple) --------------


def add_step(
    steps: tuple[AuthStep, ...], step: AuthStep, index: int | None = None
) -> tuple[AuthStep, ...]:
    """Insert ``step`` at ``index`` (default: append at the end)."""
    items = list(steps)
    if index is None:
        index = len(items)
    index = max(0, min(index, len(items)))
    items.insert(index, step)
    return tuple(items)


def remove_step(steps: tuple[AuthStep, ...], index: int) -> tuple[AuthStep, ...]:
    items = list(steps)
    if 0 <= index < len(items):
        del items[index]
    return tuple(items)


def duplicate_step(steps: tuple[AuthStep, ...], index: int) -> tuple[AuthStep, ...]:
    items = list(steps)
    if 0 <= index < len(items):
        items.insert(index + 1, items[index])
    return tuple(items)


def move_step(steps: tuple[AuthStep, ...], index: int, direction: int) -> tuple[AuthStep, ...]:
    """Move the step at ``index`` by ``direction`` (-1 = up, +1 = down).
    A no-op (returns ``steps`` unchanged) if the move would go out of
    bounds -- callers don't need to bounds-check before calling."""
    items = list(steps)
    target = index + direction
    if not (0 <= index < len(items) and 0 <= target < len(items)):
        return steps
    items[index], items[target] = items[target], items[index]
    return tuple(items)


def update_step(steps: tuple[AuthStep, ...], index: int, **changes: object) -> tuple[AuthStep, ...]:
    """Replace the step at ``index`` with a copy that has ``changes``
    applied (e.g. ``update_step(steps, 0, value="ctrl+v")``)."""
    items = list(steps)
    if 0 <= index < len(items):
        items[index] = replace(items[index], **changes)
    return tuple(items)


def toggle_enabled(steps: tuple[AuthStep, ...], index: int) -> tuple[AuthStep, ...]:
    items = list(steps)
    if 0 <= index < len(items):
        items[index] = replace(items[index], enabled=not items[index].enabled)
    return tuple(items)


# -- preview / human-readable summary ---------------------------------------


def preview_text(steps: tuple[AuthStep, ...]) -> str:
    """``"Username -> Tab -> Password -> Enter -> Wait 1500ms -> TOTP -> Enter"``
    -- disabled steps are shown in brackets so the preview still
    reflects exactly what will (and won't) run."""
    parts = []
    for step in steps:
        label = STEP_LABELS.get(step.action, step.action.value)
        if step.action == StepAction.WAIT:
            ms = step.value if step.value is not None else "0"
            label = f"Wait {ms}ms"
        elif step.action == StepAction.KEY_COMBO and step.value:
            label = f"Key ({step.value})"
        elif step.action == StepAction.FOCUS_FIELD and step.field_hint:
            label = f"Focus ({step.field_hint})"
        parts.append(label if step.enabled else f"[{label}]")
    return " -> ".join(parts) if parts else "(empty -- nothing will happen)"


# -- validation ---------------------------------------------------------------


def validate_strategy(
    steps: tuple[AuthStep, ...],
    *,
    account_has_totp: bool,
    account_has_username: bool = True,
    account_has_password: bool = True,
) -> list[str]:
    """Return a list of human-readable problems; empty list = valid,
    safe to save. Never raises -- always returns a list, even for
    completely empty/garbage input, so the editor can always show
    *something* actionable rather than crashing on a bad state.

    ``account_has_username``/``account_has_password`` default to True
    (permissive) because every normal entry has both -- pass the real
    ``AccountSummary.has_username``/``has_password`` values to catch the
    unusual case of an entry with one deliberately left blank."""
    problems: list[str] = []
    enabled_steps = [s for s in steps if s.enabled]

    if not any(s.action in _SECRET_STEPS for s in enabled_steps):
        problems.append("At least one input step (Username, Password, or TOTP) is required.")

    for i, step in enumerate(steps, start=1):
        if step.action == StepAction.WAIT and not validate_wait_ms(step.value or ""):
            problems.append(
                f"Step {i} (Wait): value must be a whole number of milliseconds "
                f"between {MIN_WAIT_MS} and {MAX_WAIT_MS}."
            )
        if step.action == StepAction.KEY_COMBO and not validate_key_combo(step.value or ""):
            problems.append(
                f"Step {i} (Key Combination): must be a modifier+key combo like "
                f"'ctrl+v' (letters/digits only, at least one of ctrl/shift/alt)."
            )
        if step.action == StepAction.TYPE_TOTP and step.enabled and not account_has_totp:
            problems.append(
                f"Step {i} (Type TOTP): this account has no TOTP configured -- "
                "add TOTP to the account first, or remove/disable this step."
            )
        if step.action == StepAction.TYPE_USERNAME and step.enabled and not account_has_username:
            problems.append(f"Step {i} (Type Username): this account has no username set.")
        if step.action == StepAction.TYPE_PASSWORD and step.enabled and not account_has_password:
            problems.append(f"Step {i} (Type Password): this account has no password set.")

    return problems


def is_valid(
    steps: tuple[AuthStep, ...],
    *,
    account_has_totp: bool,
    account_has_username: bool = True,
    account_has_password: bool = True,
) -> bool:
    return not validate_strategy(
        steps,
        account_has_totp=account_has_totp,
        account_has_username=account_has_username,
        account_has_password=account_has_password,
    )


# -- preset matching ----------------------------------------------------------


def matches_preset(steps: tuple[AuthStep, ...], preset: AuthStrategy) -> bool:
    """True if ``steps`` is structurally identical to ``preset``'s steps
    -- used by the editor to decide whether to show a builtin preset
    name or fall back to showing "Custom"."""
    return tuple(steps) == tuple(preset.steps)
