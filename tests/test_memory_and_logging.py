"""SecretBytes wiping + the safe-logging enforcement layer (spec section
31/32). Uses only fabricated secret-like strings."""

from __future__ import annotations

import logging

import pytest

from passman.core.security.logging import (
    UnsafeLogFieldError,
    redact_identifier,
    safe_extra,
    scrub_argv,
)
from passman.core.security.memory import SecretBytes

FAKE_SECRET = "fake-super-secret-abc123"


def test_secret_bytes_round_trips_value():
    s = SecretBytes(FAKE_SECRET)
    assert s.to_str() == FAKE_SECRET
    assert bool(s) is True


def test_secret_bytes_wipe_clears_buffer():
    s = SecretBytes(FAKE_SECRET)
    s.wipe()
    assert bool(s) is False
    with pytest.raises(ValueError):
        s.to_str()


def test_secret_bytes_repr_never_contains_value():
    s = SecretBytes(FAKE_SECRET)
    assert FAKE_SECRET not in repr(s)
    assert FAKE_SECRET not in str(s)


def test_secret_bytes_double_wipe_is_safe():
    s = SecretBytes(FAKE_SECRET)
    s.wipe()
    s.wipe()  # must not raise
    assert bool(s) is False


def test_secret_bytes_context_manager_wipes_on_exit():
    with SecretBytes(FAKE_SECRET) as s:
        assert s.to_str() == FAKE_SECRET
    assert bool(s) is False


# -- safe logging -----------------------------------------------------------


def test_safe_extra_allows_non_sensitive_fields():
    extra = safe_extra(event="login_result", outcome="success")
    assert extra == {"event": "login_result", "outcome": "success"}


@pytest.mark.parametrize(
    "field_name", ["password", "totp_secret", "totp_code", "recovery_code", "recovery_codes", "key_file", "keyfile", "secret"]
)
def test_safe_extra_refuses_forbidden_field_names(field_name):
    with pytest.raises(UnsafeLogFieldError):
        safe_extra(**{field_name: FAKE_SECRET})


def test_redact_identifier_keeps_only_prefix():
    assert redact_identifier("ash.example@mail.invalid") == "as" + "*" * (len("ash.example@mail.invalid") - 2)


def test_redact_identifier_empty_string():
    assert redact_identifier("") == ""


def test_scrub_argv_redacts_password_like_flags():
    argv = ["some-tool", "--password=hunter2", "--other", "value"]
    scrubbed = scrub_argv(argv)
    assert "hunter2" not in " ".join(scrubbed)


def test_scrub_argv_leaves_normal_args_untouched():
    argv = ["some-tool", "--verbose", "input.txt"]
    assert scrub_argv(argv) == argv


def test_logger_never_receives_forbidden_field(caplog):
    caplog.set_level(logging.INFO)
    logger = logging.getLogger("passman.test")
    with pytest.raises(UnsafeLogFieldError):
        logger.info("attempt", extra=safe_extra(password=FAKE_SECRET))
    for record in caplog.records:
        assert FAKE_SECRET not in record.getMessage()
