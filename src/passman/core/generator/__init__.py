"""Toolkit-independent password generation: deterministic templates
(ported from password-template-generator) and CSPRNG-backed random mode.

Nothing in this package imports GTK, Qt, or the vault.
"""

from .errors import (
    MissingValueError,
    TemplateError,
    TemplateSyntaxError,
    UnknownPlaceholderError,
)
from .random_generator import PolicyError, RandomPasswordPolicy, generate_random_password
from .template_engine import (
    PLACEHOLDERS,
    ResolveContext,
    generate,
    known_placeholder_names,
    parse,
    required_placeholders,
    resolve,
)

__all__ = [
    "PLACEHOLDERS",
    "MissingValueError",
    "PolicyError",
    "RandomPasswordPolicy",
    "ResolveContext",
    "TemplateError",
    "TemplateSyntaxError",
    "UnknownPlaceholderError",
    "generate",
    "generate_random_password",
    "known_placeholder_names",
    "parse",
    "required_placeholders",
    "resolve",
]
