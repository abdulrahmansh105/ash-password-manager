"""Recovery / emergency code handling.

Codes are stored inside the vault as a single protected (KDBX inner-stream
encrypted) custom string field -- see ``core.vault.kdbx`` for the exact
field name. This module only handles the JSON (de)serialization and the
explicit two-step reveal gate; it never touches the filesystem or logs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class RecoveryCode:
    """Defined here (not in ``core.vault.models``) specifically to avoid
    a vault<->recovery circular import: ``core.vault.kdbx`` needs
    ``serialize``/``deserialize`` from this module, and
    ``core.vault.models.AccountSecrets`` needs this type -- so this
    module must not import anything from ``core.vault``. Re-exported
    from ``core.vault`` for callers that only think in vault terms."""

    code: str
    used: bool = False
    label: str = ""


def serialize(codes: list[RecoveryCode]) -> str:
    return json.dumps([{"code": c.code, "used": c.used, "label": c.label} for c in codes])


def deserialize(raw: str | None) -> list[RecoveryCode]:
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    result = []
    for item in items:
        try:
            result.append(
                RecoveryCode(
                    code=item["code"],
                    used=bool(item.get("used", False)),
                    label=item.get("label", ""),
                )
            )
        except (KeyError, TypeError):
            continue
    return result


@dataclass
class RevealGate:
    """Two-step explicit confirmation before recovery codes are ever
    returned to a caller (e.g. rendered in the UI). Step 1 (``request``)
    only records intent; step 2 (``confirm``) actually releases the
    codes and must be called within ``ttl_seconds`` of the request or the
    gate resets. This is app-level UX policy, not cryptographic -- the
    real protection is that the codes are KDBX-protected-string
    encrypted at rest and never included in the account summary/list."""

    ttl_seconds: float = 10.0
    _requested_at: float | None = None

    def request(self, now: float) -> None:
        self._requested_at = now

    def confirm(self, now: float) -> bool:
        if self._requested_at is None:
            return False
        expired = (now - self._requested_at) > self.ttl_seconds
        self._requested_at = None
        return not expired

    def reset(self) -> None:
        self._requested_at = None
