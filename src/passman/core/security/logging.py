"""Safe, secret-free logging.

Every log record goes through this module rather than the stdlib
``logging`` module directly, so there is exactly one place that decides
what is safe to write. Log lines carry an event ID and generic status,
never field values that could be sensitive (passwords, TOTP secrets/
codes, recovery codes, Key File bytes, vault contents, full command
lines that embed any of the above).

Usernames are treated as potentially sensitive too (many people reuse
emails-as-usernames) and are never logged in full; only redacted.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from ..appdirs import state_home

_LOG_DIR_MODE = 0o700
_LOG_FILE_MODE = 0o600

# A conservative blocklist of key names that must never appear as values
# in a log call -- used by tests to grep the log output, and by
# `safe_extra` to refuse to log a field with a matching name outright.
_FORBIDDEN_FIELD_NAMES = {
    "password",
    "passphrase",
    "secret",
    "totp_secret",
    "totp_code",
    "recovery_code",
    "recovery_codes",
    "key_file",
    "keyfile",
    "luks_password",
}


class UnsafeLogFieldError(Exception):
    """Raised when code attempts to log a field whose name is on the
    forbidden list -- a deliberate hard failure rather than silently
    dropping the field, so the mistake is caught in development/tests."""


def log_dir() -> Path:
    return state_home()


def redact_identifier(value: str, keep: int = 2) -> str:
    """Redact a possibly-sensitive identifier (e.g. a username) for
    logging: keeps the first ``keep`` characters, replaces the rest."""
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep)


def safe_extra(**fields: object) -> dict[str, object]:
    """Build a logging ``extra`` dict, refusing any forbidden field name.

    This is the enforcement point: call sites pass named fields, and any
    name that matches the forbidden list raises immediately instead of
    being logged.
    """
    for name in fields:
        if name.lower() in _FORBIDDEN_FIELD_NAMES:
            raise UnsafeLogFieldError(
                f"Refusing to log field '{name}': matches forbidden field name list."
            )
    return fields


_SECRET_LIKE_RE = re.compile(
    r"(--?(password|passphrase|secret|totp[-_]?code|key)\S*)[= ]\S+",
    re.IGNORECASE,
)


def scrub_argv(argv: list[str]) -> list[str]:
    """Best-effort scrub of a command-line argument list before it is
    ever logged (e.g. in a crash report). Used by subprocess wrappers
    that shell out to external tools -- this project never puts secrets
    in argv/env in the first place (see core.auth / core.security), but
    this exists as defense in depth for third-party tool invocations."""
    scrubbed = []
    for arg in argv:
        if _SECRET_LIKE_RE.search(arg):
            scrubbed.append("[REDACTED]")
        else:
            scrubbed.append(arg)
    return scrubbed


_configured = False


def get_logger(name: str) -> logging.Logger:
    """Return a module logger writing to
    ``$XDG_STATE_HOME/ash-password-manager/passman.log`` with restrictive
    permissions. Configured once per process."""
    global _configured
    logger = logging.getLogger(name)
    if not _configured:
        _configure_root()
        _configured = True
    return logger


def _configure_root() -> None:
    root = logging.getLogger("passman")
    if root.handlers:
        return
    d = log_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, _LOG_DIR_MODE)
        path = d / "passman.log"
        handler = logging.FileHandler(path, encoding="utf-8")
        try:
            os.chmod(path, _LOG_FILE_MODE)
        except OSError:
            pass
    except OSError:
        handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(logging.INFO)
