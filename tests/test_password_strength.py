from __future__ import annotations

from passman.core.security.password_strength import (
    MIN_LENGTH,
    estimate_password_strength,
)


def test_empty_password_is_very_weak():
    assert estimate_password_strength("").score == 0


def test_short_password_is_very_weak_regardless_of_variety():
    assert estimate_password_strength("Ab1!").score == 0
    assert len("Ab1!") < MIN_LENGTH


def test_long_simple_password_scores_low():
    assert estimate_password_strength("aaaaaaaaaaaa").score <= 2


def test_long_varied_password_scores_high():
    result = estimate_password_strength("Tr0ub4dor&3xtra!Long")
    assert result.score == 4
    assert result.label == "Strong"


def test_score_is_monotonic_with_length_at_fixed_variety():
    scores = [estimate_password_strength("Ab1!" * n).score for n in range(2, 8)]
    assert scores == sorted(scores)
