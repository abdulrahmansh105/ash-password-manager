"""Vault-facing data models.

Split deliberately into two tiers:

- ``AccountSummary`` -- everything safe to hold in memory for the account
  picker / search list. Contains no username, password, TOTP secret, URL,
  notes, or recovery codes. This is enforced at the *type* level: code
  that only has an ``AccountSummary`` physically cannot render a secret,
  because the object doesn't carry one.
- ``AccountSecrets`` -- fetched only when an account is actually opened
  (reveal / autotype). Holds the password as ``SecretBytes`` so it can be
  wiped promptly after use.

This mirrors spec section 8 (account list must never show username/
password/TOTP/recovery codes) and section 28 (display name is a distinct
field from username/password/URL/TOTP/notes).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..recovery.codes import RecoveryCode
from ..security.memory import SecretBytes
from ..totp.totp import TotpConfig

# The Manager's category sidebar (spec section 23). Stored as the
# PM_Category custom KDBX field (see core.vault.kdbx) -- an ordinary,
# non-secret, freeform string, but constrained here to a fixed set so
# the sidebar is stable and every entry lands in exactly one place.
DEFAULT_CATEGORY = "logins"
CATEGORY_LABELS: dict[str, str] = {
    "logins": "Logins",
    "software": "Software",
    "wifi": "Wi-Fi",
    "secure_notes": "Secure Notes",
    "other": "Other",
}
CATEGORY_CHOICES: tuple[str, ...] = tuple(CATEGORY_LABELS)


def normalize_category(value: str | None) -> str:
    return value if value in CATEGORY_LABELS else DEFAULT_CATEGORY


@dataclass(frozen=True)
class AccountSummary:
    """Safe for the account picker, search index, and suggestion ranking."""

    entry_uuid: str
    display_name: str
    service_name: str
    icon_ref: str | None = None
    tags: tuple[str, ...] = ()
    has_totp: bool = False
    has_recovery_codes: bool = False
    # Presence-only booleans (never the values themselves) -- used by
    # the Auto-Type strategy editor's validation (a Type Username/
    # Password step only makes sense if the field is actually
    # populated), without needing to fetch AccountSecrets for it.
    has_username: bool = False
    has_password: bool = False
    category: str = DEFAULT_CATEGORY


@dataclass
class AccountSecrets:
    """Only constructed on explicit open (reveal/autotype). Callers must
    call ``wipe()`` (or use as a context manager) when done."""

    entry_uuid: str
    display_name: str
    service_name: str
    username: str
    password: SecretBytes
    url: str
    notes: str
    app_identifiers: tuple[str, ...]
    auth_strategy_json: str | None
    totp: TotpConfig | None
    recovery_codes: list[RecoveryCode] = field(default_factory=list)
    category: str = DEFAULT_CATEGORY

    def wipe(self) -> None:
        self.password.wipe()
        self.recovery_codes.clear()

    def __enter__(self) -> "AccountSecrets":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.wipe()

    def __repr__(self) -> str:  # never render secret fields
        return f"AccountSecrets(entry_uuid={self.entry_uuid!r}, display_name={self.display_name!r})"
