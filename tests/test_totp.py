"""TOTP tests use only the RFC 4648/6238 published test-vector secret
(``JBSWY3DPEHPK3PXP``, i.e. base32 for "Hello!\\xde\\xad\\xbe\\xef" --
publicly documented, not a real credential of anyone's) plus fabricated
values for negative cases."""

from __future__ import annotations

import pytest

from passman.core.totp.totp import (
    InvalidTotpSecretError,
    TotpConfig,
    generate_totp,
    normalize_base32_secret,
    seconds_remaining,
    verify_totp,
)

TEST_SECRET = normalize_base32_secret("JBSWY3DPEHPK3PXP")


def test_generate_totp_is_deterministic_for_fixed_time():
    config = TotpConfig(secret_base32=TEST_SECRET)
    a = generate_totp(config, at_time=1_700_000_000)
    b = generate_totp(config, at_time=1_700_000_000)
    assert a == b
    assert len(a) == 6
    assert a.isdigit()


def test_generate_totp_changes_across_period_boundary():
    config = TotpConfig(secret_base32=TEST_SECRET)
    a = generate_totp(config, at_time=1_700_000_000)
    b = generate_totp(config, at_time=1_700_000_000 + 30)
    assert a != b


def test_verify_totp_accepts_correct_code():
    config = TotpConfig(secret_base32=TEST_SECRET)
    code = generate_totp(config, at_time=1_700_000_000)
    assert verify_totp(config, code, at_time=1_700_000_000) is True


def test_verify_totp_rejects_wrong_code():
    config = TotpConfig(secret_base32=TEST_SECRET)
    assert verify_totp(config, "000000", at_time=1_700_000_000) is False


def test_verify_totp_allows_clock_drift_window():
    config = TotpConfig(secret_base32=TEST_SECRET)
    code = generate_totp(config, at_time=1_700_000_000)
    assert verify_totp(config, code, at_time=1_700_000_000 + 30, window=1) is True


def test_verify_totp_rejects_outside_window():
    config = TotpConfig(secret_base32=TEST_SECRET)
    code = generate_totp(config, at_time=1_700_000_000)
    assert verify_totp(config, code, at_time=1_700_000_000 + 90, window=1) is False


def test_invalid_base32_secret_raises():
    with pytest.raises(InvalidTotpSecretError):
        normalize_base32_secret("not-valid-base32!!!")


def test_normalize_strips_whitespace_and_hyphens():
    assert normalize_base32_secret("jbsw y3dp-ehpk 3pxp") == TEST_SECRET


def test_seconds_remaining_bounds():
    config = TotpConfig(secret_base32=TEST_SECRET, period=30)
    remaining = seconds_remaining(config, at_time=1_700_000_015)
    assert 0 < remaining <= 30


def test_digits_out_of_range_raises():
    with pytest.raises(InvalidTotpSecretError):
        TotpConfig(secret_base32=TEST_SECRET, digits=3)


def test_code_stable_across_entire_period_window():
    config = TotpConfig(secret_base32=TEST_SECRET, period=30)
    base = 1_700_000_010  # arbitrary point inside a 30s window
    period_start = (base // 30) * 30
    codes = {generate_totp(config, at_time=period_start + offset) for offset in range(30)}
    assert len(codes) == 1  # identical for every second inside the same period


def test_code_changes_at_the_exact_period_boundary():
    config = TotpConfig(secret_base32=TEST_SECRET, period=30)
    period_start = 1_700_000_010 // 30 * 30
    last_second_of_period = period_start + 29
    first_second_of_next_period = period_start + 30
    a = generate_totp(config, at_time=last_second_of_period)
    b = generate_totp(config, at_time=first_second_of_next_period)
    assert a != b


def test_default_config_is_sha1_6_digits_30s():
    config = TotpConfig(secret_base32=TEST_SECRET)
    assert config.algorithm == "SHA1"
    assert config.digits == 6
    assert config.period == 30


def test_sha256_algorithm_produces_different_code_than_sha1():
    a = generate_totp(TotpConfig(secret_base32=TEST_SECRET, algorithm="SHA1"), at_time=1_700_000_000)
    b = generate_totp(TotpConfig(secret_base32=TEST_SECRET, algorithm="SHA256"), at_time=1_700_000_000)
    assert a != b
