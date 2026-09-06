from __future__ import annotations

import string

import pytest

from passman.core.generator import (
    PolicyError,
    RandomPasswordPolicy,
    generate_random_password,
)


def test_default_policy_length():
    pw = generate_random_password(RandomPasswordPolicy())
    assert len(pw) == 24


def test_no_character_classes_raises():
    policy = RandomPasswordPolicy(use_lower=False, use_upper=False, use_digits=False, use_symbols=False)
    with pytest.raises(PolicyError):
        generate_random_password(policy)


def test_length_too_short_for_classes_raises():
    policy = RandomPasswordPolicy(length=2, use_lower=True, use_upper=True, use_digits=True, use_symbols=True)
    with pytest.raises(PolicyError):
        generate_random_password(policy)


def test_only_digits():
    policy = RandomPasswordPolicy(length=16, use_lower=False, use_upper=False, use_digits=True, use_symbols=False)
    pw = generate_random_password(policy)
    assert all(c in string.digits for c in pw)


def test_exclude_ambiguous():
    policy = RandomPasswordPolicy(length=200, use_symbols=False, exclude_ambiguous=True)
    pw = generate_random_password(policy)
    assert not any(c in "Il1O0" for c in pw)


def test_two_generations_differ():
    policy = RandomPasswordPolicy(length=32)
    a = generate_random_password(policy)
    b = generate_random_password(policy)
    assert a != b


def test_all_classes_present_when_length_allows():
    policy = RandomPasswordPolicy(length=32)
    pw = generate_random_password(policy)
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.ascii_uppercase for c in pw)
    assert any(c in string.digits for c in pw)
    assert any(c in policy.symbols for c in pw)
