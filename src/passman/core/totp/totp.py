"""RFC 6238 TOTP (Time-based One-Time Password) generation and secret
handling.

Hand-rolled on top of stdlib ``hmac``/``hashlib``/``base64`` rather than
depending on a third-party TOTP library (e.g. ``pyotp``). The algorithm is
~20 lines of well-specified, easily auditable code; pulling in an extra
dependency for it is not worth the added supply-chain surface for a vault
application. RFC 6238 / RFC 4226 are followed exactly (HOTP counter =
floor(unix_time / period), dynamic truncation per RFC 4226 §5.3).

Secrets are handled as ``bytes`` for as short a time as practical and are
never logged (see ``core.security.logging``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
from dataclasses import dataclass

_ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")


class InvalidTotpSecretError(Exception):
    """Raised when a TOTP secret is not valid base32, without ever
    including the offending value in the message."""


def normalize_base32_secret(raw: str) -> str:
    """Strip whitespace/hyphens and uppercase a user-entered base32 secret.

    Raises ``InvalidTotpSecretError`` (message never contains the secret)
    if the result is not valid base32.
    """
    cleaned = re.sub(r"[\s-]", "", raw).upper()
    # Restore correct padding (base32 needs len % 8 == 0).
    padding = (-len(cleaned)) % 8
    cleaned += "=" * padding
    if not cleaned or not _BASE32_RE.fullmatch(cleaned):
        raise InvalidTotpSecretError("TOTP secret is not valid base32.")
    try:
        base64.b32decode(cleaned)
    except Exception as exc:
        raise InvalidTotpSecretError("TOTP secret is not valid base32.") from exc
    return cleaned


@dataclass(frozen=True)
class TotpConfig:
    secret_base32: str  # normalized, padded base32
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"  # SHA1 is what virtually every real-world
    # authenticator app / service supports; SHA256/SHA512 are offered for
    # completeness but most services silently expect SHA1 regardless of
    # what they claim.

    def __post_init__(self) -> None:
        if self.algorithm not in _ALGOS:
            raise InvalidTotpSecretError(f"Unsupported TOTP algorithm: {self.algorithm}")
        if not (6 <= self.digits <= 10):
            raise InvalidTotpSecretError("TOTP digit count must be between 6 and 10.")
        if self.period <= 0:
            raise InvalidTotpSecretError("TOTP period must be positive.")


def _hotp(secret_bytes: bytes, counter: int, digits: int, algorithm: str) -> str:
    counter_bytes = counter.to_bytes(8, "big")
    digest = hmac.new(secret_bytes, counter_bytes, _ALGOS[algorithm]).digest()
    offset = digest[-1] & 0x0F
    truncated = digest[offset : offset + 4]
    code_int = int.from_bytes(truncated, "big") & 0x7FFFFFFF
    code = code_int % (10**digits)
    return str(code).zfill(digits)


def generate_totp(config: TotpConfig, at_time: float | None = None) -> str:
    """Generate the current (or ``at_time``) TOTP code for ``config``."""
    t = time.time() if at_time is None else at_time
    counter = int(t // config.period)
    secret_bytes = base64.b32decode(config.secret_base32)
    return _hotp(secret_bytes, counter, config.digits, config.algorithm)


def seconds_remaining(config: TotpConfig, at_time: float | None = None) -> int:
    """Seconds until the current TOTP code expires."""
    t = time.time() if at_time is None else at_time
    return config.period - int(t % config.period)


def verify_totp(
    config: TotpConfig, code: str, at_time: float | None = None, window: int = 1
) -> bool:
    """Verify ``code`` against ``config``, allowing +/- ``window`` periods
    of clock drift. Used only for the account's own "Test TOTP" action --
    never logs the code either way."""
    t = time.time() if at_time is None else at_time
    counter = int(t // config.period)
    secret_bytes = base64.b32decode(config.secret_base32)
    for offset in range(-window, window + 1):
        candidate = _hotp(secret_bytes, counter + offset, config.digits, config.algorithm)
        if hmac.compare_digest(candidate, code):
            return True
    return False
