"""Ported from password-template-generator's tests/test_engine.py --
same behavior, same coverage, new import path. If this file's assertions
ever diverge from that project's, the port broke something."""

from __future__ import annotations

import pytest

from passman.core.generator import (
    MissingValueError,
    TemplateSyntaxError,
    UnknownPlaceholderError,
    generate,
    known_placeholder_names,
    required_placeholders,
)


def test_basic_username_and_service():
    assert generate("{USERNAME}-{SERVICE_NAME}", username="ash", service_name="Discord") == "ash-Discord"


def test_username_fallback_used_when_empty():
    assert generate("{USERNAME || ASH}", username="", service_name="") == "ASH"


def test_username_fallback_ignored_when_present():
    assert generate("{USERNAME || ASH}", username="bob", service_name="") == "bob"


def test_whitespace_around_fallback_pipe_ignored():
    assert generate("{USERNAME||ASH}", username="", service_name="") == generate(
        "{USERNAME  ||  ASH}", username="", service_name=""
    )


def test_case_insensitive_placeholder_name():
    assert generate("{username}", username="ash", service_name="") == "ash"


def test_missing_username_no_fallback_raises():
    with pytest.raises(MissingValueError):
        generate("{USERNAME}", username="", service_name="")


def test_missing_service_raises():
    with pytest.raises(MissingValueError):
        generate("{SERVICE_NAME}", username="ash", service_name="")


def test_unknown_placeholder_raises():
    with pytest.raises(UnknownPlaceholderError):
        generate("{NOT_A_FIELD}", username="ash", service_name="Discord")


@pytest.mark.parametrize("template", ["{USERNAME", "USERNAME}", "{US{ER}NAME}", "{ || X}", "{USERNAME || }"])
def test_malformed_syntax_raises(template):
    with pytest.raises(TemplateSyntaxError):
        generate(template, username="ash", service_name="Discord")


def test_unicode_values_round_trip():
    assert generate("{USERNAME}-{SERVICE_NAME}", username="äsh", service_name="Ðiscord") == "äsh-Ðiscord"


def test_required_placeholders():
    assert required_placeholders("{USERNAME}-{SERVICE_NAME}") == {"USERNAME", "SERVICE_NAME"}


def test_known_placeholder_names_sorted():
    names = known_placeholder_names()
    assert names == sorted(names)
    assert "USERNAME" in names and "SERVICE_NAME" in names


def test_deterministic_same_inputs_same_output():
    a = generate("#Tpl{USERNAME}{SERVICE_NAME}911", username="ash", service_name="Discord")
    b = generate("#Tpl{USERNAME}{SERVICE_NAME}911", username="ash", service_name="Discord")
    assert a == b
