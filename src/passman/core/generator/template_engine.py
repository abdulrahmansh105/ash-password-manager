"""Template parsing and resolution engine.

This module has no dependency on any GUI toolkit or on the vault. It is
ported unchanged (behavior-for-behavior) from password-template-generator's
``ptgen.core.engine``, which this whole application grew out of. Existing
templates from that project resolve identically here.

Grammar
-------
A template is literal text interspersed with placeholders of the form::

    {NAME}
    {NAME || FALLBACK}

- ``NAME`` is case-insensitive and matches ``[A-Za-z_][A-Za-z0-9_]*``.
- Whitespace around ``||`` and around ``NAME`` is ignored.
- ``FALLBACK`` is raw text, trimmed of leading/trailing whitespace, that
  must not be empty if ``||`` is present.
- Placeholders do not nest.

Extensibility
-------------
Supported placeholders are declared in ``PLACEHOLDERS`` below as
``PlaceholderSpec`` entries. Adding a new placeholder (e.g. a future
``{YEAR}``) means adding one entry with a resolver function -- nothing
else in the engine, GUI, or CLI needs to change.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .errors import MissingValueError, TemplateSyntaxError, UnknownPlaceholderError

_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Keep previews/snippets in error messages bounded so a huge template
# cannot produce an unreadable (or huge) error message.
_SNIPPET_LIMIT = 40


def _snippet(text: str) -> str:
    if len(text) <= _SNIPPET_LIMIT:
        return text
    return text[:_SNIPPET_LIMIT] + "..."


@dataclass(frozen=True)
class ResolveContext:
    """Values available for resolving placeholders.

    Values are used exactly as provided; the engine does not strip or
    otherwise mutate them. A value is considered "empty" only when it is
    the empty string.
    """

    username: str = ""
    service_name: str = ""


@dataclass(frozen=True)
class PlaceholderSpec:
    name: str  # canonical, upper-case
    supports_fallback: bool
    resolver: Callable[[ResolveContext, str | None], str]
    description: str = ""


def _resolve_username(ctx: ResolveContext, fallback: str | None) -> str:
    if ctx.username:
        return ctx.username
    if fallback is not None:
        return fallback
    raise MissingValueError(
        "Username is required because the template contains {USERNAME}."
    )


def _resolve_service_name(ctx: ResolveContext, fallback: str | None) -> str:
    if ctx.service_name:
        return ctx.service_name
    if fallback is not None:
        return fallback
    raise MissingValueError("Service name is required.")


PLACEHOLDERS: dict[str, PlaceholderSpec] = {
    "USERNAME": PlaceholderSpec(
        name="USERNAME",
        supports_fallback=True,
        resolver=_resolve_username,
        description="Uses the entered username, or the fallback text (if given) when empty.",
    ),
    "SERVICE_NAME": PlaceholderSpec(
        name="SERVICE_NAME",
        supports_fallback=True,
        resolver=_resolve_service_name,
        description="Uses the entered service name, or the fallback text (if given) when empty.",
    ),
}


class _Literal:
    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


class _Placeholder:
    __slots__ = ("canonical_name", "fallback")

    def __init__(self, canonical_name: str, fallback: str | None) -> None:
        self.canonical_name = canonical_name
        self.fallback = fallback


Token = "_Literal | _Placeholder"


def _parse_placeholder_body(inner: str, raw: str) -> _Placeholder:
    has_fallback = "||" in inner
    if has_fallback:
        name_part, _, fallback_part = inner.partition("||")
    else:
        name_part, fallback_part = inner, None

    name = name_part.strip()
    if not name:
        raise TemplateSyntaxError(
            f'Invalid template syntax near "{_snippet(raw)}": placeholder name is empty.'
        )
    if not _NAME_RE.fullmatch(name):
        raise TemplateSyntaxError(
            f'Invalid template syntax near "{_snippet(raw)}": '
            f'"{name}" is not a valid placeholder name.'
        )

    fallback: str | None = None
    if has_fallback:
        fallback = fallback_part.strip()
        if fallback == "":
            raise TemplateSyntaxError(
                f'Invalid template syntax near "{_snippet(raw)}": '
                f'fallback value after "||" cannot be empty.'
            )

    canonical = name.upper()
    spec = PLACEHOLDERS.get(canonical)
    if spec is None:
        raise UnknownPlaceholderError(f"Unknown placeholder: {{{name}}}")

    if fallback is not None and not spec.supports_fallback:
        raise TemplateSyntaxError(
            f'Invalid template syntax near "{_snippet(raw)}": '
            f"{{{canonical}}} does not support a fallback value."
        )

    return _Placeholder(canonical, fallback)


def parse(template: str) -> list:
    """Parse ``template`` into a list of literal and placeholder tokens.

    Raises ``TemplateSyntaxError`` or ``UnknownPlaceholderError`` on
    malformed or unrecognized input. Never raises on valid syntax
    regardless of username/service values -- those are checked later,
    during resolution.
    """
    tokens: list = []
    i = 0
    n = len(template)
    literal_start = 0

    while i < n:
        ch = template[i]
        if ch == "{":
            if i > literal_start:
                tokens.append(_Literal(template[literal_start:i]))
            close = template.find("}", i + 1)
            if close == -1:
                raise TemplateSyntaxError(
                    f'Invalid template syntax near "{_snippet(template[i:])}": '
                    f'missing closing "}}".'
                )
            inner = template[i + 1 : close]
            if "{" in inner:
                raise TemplateSyntaxError(
                    f'Invalid template syntax near "{_snippet(template[i:close + 1])}": '
                    f'nested "{{" is not allowed.'
                )
            raw = template[i : close + 1]
            tokens.append(_parse_placeholder_body(inner, raw))
            i = close + 1
            literal_start = i
        elif ch == "}":
            context = template[max(0, i - 10) : i + 1]
            raise TemplateSyntaxError(
                f'Invalid template syntax near "{_snippet(context)}": '
                f'unexpected "}}" with no matching "{{".'
            )
        else:
            i += 1

    if i > literal_start:
        tokens.append(_Literal(template[literal_start:i]))

    return tokens


def known_placeholder_names() -> list[str]:
    """Canonical names of all registered placeholders, for help text."""
    return sorted(PLACEHOLDERS.keys())


def resolve(tokens: list, ctx: ResolveContext) -> str:
    """Resolve already-parsed ``tokens`` against ``ctx``.

    Raises ``MissingValueError`` if a required value is missing.
    """
    parts: list[str] = []
    for tok in tokens:
        if isinstance(tok, _Literal):
            parts.append(tok.text)
        else:
            spec = PLACEHOLDERS[tok.canonical_name]
            parts.append(spec.resolver(ctx, tok.fallback))
    return "".join(parts)


def generate(template: str, username: str = "", service_name: str = "") -> str:
    """Parse and resolve ``template`` in one step.

    This is the single entry point both the GUI and the CLI use to turn
    a template into a final password. Raises ``TemplateError`` subclasses
    on any problem; never returns a partially-resolved result.
    """
    tokens = parse(template)
    ctx = ResolveContext(username=username, service_name=service_name)
    return resolve(tokens, ctx)


def required_placeholders(template: str) -> set[str]:
    """Canonical names of placeholders referenced by ``template``.

    Useful for the GUI to decide, ahead of generation, which fields to
    mark as relevant/required without needing a username or service
    value yet. Raises on malformed syntax, same as ``parse``.
    """
    tokens = parse(template)
    return {tok.canonical_name for tok in tokens if isinstance(tok, _Placeholder)}
