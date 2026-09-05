from __future__ import annotations

from passman.core.accounts.repository import rank_by_context, search, suggested_and_other
from passman.core.auth.detection import Confidence, DetectedContext, match_confidence
from passman.core.vault.models import AccountSummary


def _acc(uuid: str, name: str, service: str) -> AccountSummary:
    return AccountSummary(entry_uuid=uuid, display_name=name, service_name=service)


# -- match_confidence ---------------------------------------------------


def test_high_confidence_on_window_class_match():
    ctx = DetectedContext(app_id="discord", window_title="General - my-server")
    assert match_confidence(ctx, ("discord",)) == Confidence.HIGH


def test_low_confidence_on_title_only_match():
    ctx = DetectedContext(app_id="firefox", window_title="Discord | my-server")
    assert match_confidence(ctx, ("discord",)) == Confidence.LOW


def test_unknown_confidence_when_nothing_matches():
    ctx = DetectedContext(app_id="firefox", window_title="Unrelated page")
    assert match_confidence(ctx, ("discord",)) == Confidence.UNKNOWN


def test_unknown_confidence_when_detection_totally_failed():
    ctx = DetectedContext(app_id=None, window_title=None)
    assert match_confidence(ctx, ("discord",)) == Confidence.UNKNOWN


def test_regex_pattern_supported():
    ctx = DetectedContext(app_id="Google-chrome", window_title="Sign in - Accounts")
    assert match_confidence(ctx, ("re:^google",)) == Confidence.HIGH


def test_bad_regex_pattern_does_not_crash():
    ctx = DetectedContext(app_id="discord", window_title=None)
    # An invalid regex must never raise -- it's just treated as no match.
    assert match_confidence(ctx, ("re:([",)) == Confidence.UNKNOWN


# -- search: never touches secrets, only display_name/service_name -----


def test_search_matches_display_name():
    accounts = [_acc("1", "My Personal Discord", "Discord"), _acc("2", "Work GitHub", "GitHub")]
    assert [a.entry_uuid for a in search(accounts, "disc")] == ["1"]


def test_search_matches_service_name():
    accounts = [_acc("1", "My Personal Discord", "Discord"), _acc("2", "Work GitHub", "GitHub")]
    assert [a.entry_uuid for a in search(accounts, "github")] == ["2"]


def test_search_empty_query_returns_all():
    accounts = [_acc("1", "A", "A"), _acc("2", "B", "B")]
    assert len(search(accounts, "")) == 2


def test_search_is_case_insensitive():
    accounts = [_acc("1", "My Personal Discord", "Discord")]
    assert len(search(accounts, "DISCORD")) == 1


# -- ranking: suggests, never filters out other accounts ----------------


def test_ranking_never_drops_accounts():
    accounts = [_acc("1", "Discord", "Discord"), _acc("2", "GitHub", "GitHub"), _acc("3", "Steam", "Steam")]
    ids = {"1": ("discord",), "2": ("github",), "3": ("steam",)}
    ctx = DetectedContext(app_id="discord", window_title=None)
    ranked = rank_by_context(accounts, ctx, ids)
    assert len(ranked) == 3


def test_suggested_and_other_split():
    accounts = [_acc("1", "Discord", "Discord"), _acc("2", "GitHub", "GitHub")]
    ids = {"1": ("discord",), "2": ("github",)}
    ctx = DetectedContext(app_id="discord", window_title=None)
    ranked = rank_by_context(accounts, ctx, ids)
    suggested, other = suggested_and_other(ranked)
    assert [a.entry_uuid for a in suggested] == ["1"]
    assert [a.entry_uuid for a in other] == ["2"]


def test_no_match_puts_everything_in_other():
    accounts = [_acc("1", "Discord", "Discord")]
    ids = {"1": ("discord",)}
    ctx = DetectedContext(app_id=None, window_title=None)
    ranked = rank_by_context(accounts, ctx, ids)
    suggested, other = suggested_and_other(ranked)
    assert suggested == []
    assert len(other) == 1
