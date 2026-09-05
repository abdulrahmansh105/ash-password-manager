"""Account search and suggestion ranking over ``AccountSummary`` objects
only -- never touches secrets (spec section 9: search must not expose
username/password; section 10: suggestion ranks, never filters)."""

from __future__ import annotations

from dataclasses import dataclass

from ..auth.detection import Confidence, DetectedContext, match_confidence
from ..vault.models import AccountSummary


def search(accounts: list[AccountSummary], query: str) -> list[AccountSummary]:
    """Case-insensitive substring match against display name and service
    name only. Empty query returns all accounts, display-name order."""
    q = query.strip().lower()
    if not q:
        return list(accounts)
    return [
        a
        for a in accounts
        if q in a.display_name.lower() or q in a.service_name.lower()
    ]


@dataclass(frozen=True)
class RankedAccount:
    account: AccountSummary
    confidence: Confidence


def rank_by_context(
    accounts: list[AccountSummary],
    context: DetectedContext,
    app_identifiers_by_uuid: dict[str, tuple[str, ...]],
) -> list[RankedAccount]:
    """Rank every account by how well it matches the currently detected
    window, without dropping any account (section 10: suggested ranking
    is allowed, forced filtering is not). Callers render the top HIGH/LOW
    match(es) under "Suggested" and everything else under "Other
    accounts", in the same order otherwise."""
    ranked = []
    for a in accounts:
        ids = app_identifiers_by_uuid.get(a.entry_uuid, ())
        confidence = match_confidence(context, ids)
        ranked.append(RankedAccount(account=a, confidence=confidence))

    order = {Confidence.HIGH: 0, Confidence.LOW: 1, Confidence.UNKNOWN: 2}
    ranked.sort(key=lambda r: order[r.confidence])
    return ranked


def suggested_and_other(
    ranked: list[RankedAccount],
) -> tuple[list[AccountSummary], list[AccountSummary]]:
    """Split a ranked list into (suggested, other) for the UI's two
    sections. "Suggested" is every HIGH-confidence match (usually 0 or 1,
    but never silently drops a second legitimate match, e.g. two windows
    of the same app); everything else is "Other accounts", preserving
    original relative order."""
    suggested = [r.account for r in ranked if r.confidence == Confidence.HIGH]
    other = [r.account for r in ranked if r.confidence != Confidence.HIGH]
    return suggested, other
