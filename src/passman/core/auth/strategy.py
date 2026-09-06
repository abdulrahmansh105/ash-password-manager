"""Per-account login strategy model (spec section 13).

A strategy is an ordered list of steps. It is stored per-account inside
the vault (see ``core.vault.kdbx``, custom property ``PM_AuthStrategy``)
as JSON -- it contains no secrets, only navigation instructions, so it is
stored unprotected (visible like any other KeePassXC custom string).

Steps are deliberately generic (not "Discord-specific"): they describe
what to type/press/wait-for, and the executor (``core.auth.engine``)
maps ``type_username``/``type_password``/``type_totp`` onto the actual
secret values at execution time, so the strategy JSON itself never
contains a secret even transiently.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum


class StepAction(str, Enum):
    TYPE_USERNAME = "type_username"
    TYPE_PASSWORD = "type_password"
    TYPE_TOTP = "type_totp"
    KEY_TAB = "key_tab"
    KEY_ENTER = "key_enter"
    KEY_ESCAPE = "key_escape"
    KEY_COMBO = "key_combo"  # value = e.g. "ctrl+a"
    WAIT = "wait"  # value = milliseconds, as a string
    FOCUS_FIELD = "focus_field"  # field_hint = "username" | "password" | "totp"


@dataclass(frozen=True)
class AuthStep:
    action: StepAction
    value: str | None = None
    field_hint: str | None = None
    timeout_ms: int = 4000
    retries: int = 0
    # Added for the strategy editor's enable/disable-without-deleting
    # requirement. Absent in any strategy JSON written before this field
    # existed -- from_dict() defaults it to True so every pre-existing
    # PM_AuthStrategy value continues to execute exactly as before.
    enabled: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["action"] = self.action.value
        return d

    @staticmethod
    def from_dict(d: dict) -> AuthStep:
        return AuthStep(
            action=StepAction(d["action"]),
            value=d.get("value"),
            field_hint=d.get("field_hint"),
            timeout_ms=int(d.get("timeout_ms", 4000)),
            retries=int(d.get("retries", 0)),
            enabled=bool(d.get("enabled", True)),
        )


@dataclass(frozen=True)
class AuthStrategy:
    steps: tuple[AuthStep, ...]
    name: str = "default"

    def to_json(self) -> str:
        return json.dumps({"name": self.name, "steps": [s.to_dict() for s in self.steps]})

    @staticmethod
    def from_json(raw: str | None) -> AuthStrategy:
        if not raw:
            return DEFAULT_STRATEGY
        try:
            data = json.loads(raw)
            steps = tuple(AuthStep.from_dict(s) for s in data["steps"])
            return AuthStrategy(steps=steps, name=data.get("name", "default"))
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            return DEFAULT_STRATEGY


# username -> tab -> password -> enter -> wait -> totp -> enter
DEFAULT_STRATEGY = AuthStrategy(
    name="default",
    steps=(
        AuthStep(action=StepAction.TYPE_USERNAME, field_hint="username"),
        AuthStep(action=StepAction.KEY_TAB),
        AuthStep(action=StepAction.TYPE_PASSWORD, field_hint="password"),
        AuthStep(action=StepAction.KEY_ENTER),
        AuthStep(action=StepAction.WAIT, value="1500"),
        AuthStep(action=StepAction.TYPE_TOTP, field_hint="totp"),
        AuthStep(action=StepAction.KEY_ENTER),
    ),
)

# email -> next -> password -> next -> totp -> submit (e.g. Google-style
# multi-page login where each field is its own page).
MULTI_PAGE_STRATEGY = AuthStrategy(
    name="multi_page",
    steps=(
        AuthStep(action=StepAction.TYPE_USERNAME, field_hint="username"),
        AuthStep(action=StepAction.KEY_ENTER),
        AuthStep(action=StepAction.WAIT, value="1200"),
        AuthStep(action=StepAction.TYPE_PASSWORD, field_hint="password"),
        AuthStep(action=StepAction.KEY_ENTER),
        AuthStep(action=StepAction.WAIT, value="1200"),
        AuthStep(action=StepAction.TYPE_TOTP, field_hint="totp"),
        AuthStep(action=StepAction.KEY_ENTER),
    ),
)

# password only, no username field re-entered (e.g. an already-known-user
# re-auth prompt), no TOTP.
PASSWORD_ONLY_STRATEGY = AuthStrategy(
    name="password_only",
    steps=(
        AuthStep(action=StepAction.TYPE_PASSWORD, field_hint="password"),
        AuthStep(action=StepAction.KEY_ENTER),
    ),
)

BUILTIN_STRATEGIES = {
    s.name: s for s in (DEFAULT_STRATEGY, MULTI_PAGE_STRATEGY, PASSWORD_ONLY_STRATEGY)
}
