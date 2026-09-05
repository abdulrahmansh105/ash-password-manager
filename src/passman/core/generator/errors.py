"""Exceptions raised by the template engine.

All messages are safe to display to the user and to write to logs: they
never contain resolved/generated password material, only template text,
placeholder names, and field names.

Ported unchanged from password-template-generator's ptgen.core.errors.
"""

from __future__ import annotations


class TemplateError(Exception):
    """Base class for all template engine errors."""


class TemplateSyntaxError(TemplateError):
    """The template text itself is malformed (unbalanced braces, empty
    placeholder name, empty fallback, etc.)."""


class UnknownPlaceholderError(TemplateError):
    """The template references a placeholder that is not registered."""


class MissingValueError(TemplateError):
    """A placeholder needed a value (username, service name, ...) that
    was not supplied and has no fallback."""
