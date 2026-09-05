"""Local, dependency-free password strength heuristic (spec section
3's "Password strength indicator"). Deliberately not a full entropy/
crack-time model (no zxcvbn-style dependency) -- a simple,
length-and-character-class heuristic that is honest about being
guidance, not a security boundary. The real security barrier is the
master-password key slot's Argon2id cost (``core.crypto.kdf``); this
module only steers users away from obviously weak choices during
setup.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MIN_LENGTH = 8

_CLASS_PATTERNS = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"[0-9]"),
    re.compile(r"[^a-zA-Z0-9]"),
)

_LABELS = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong"}


@dataclass(frozen=True)
class PasswordStrength:
    score: int  # 0-4
    label: str


def count_character_classes(password: str) -> int:
    return sum(1 for pattern in _CLASS_PATTERNS if pattern.search(password))


def estimate_password_strength(password: str) -> PasswordStrength:
    length = len(password)
    if length < MIN_LENGTH:
        return PasswordStrength(0, _LABELS[0])

    variety = count_character_classes(password)
    if length >= 20 and variety >= 3:
        score = 4
    elif length >= 16 and variety >= 2:
        score = 3
    elif length >= 12:
        score = 2
    else:
        score = 1
    return PasswordStrength(score=score, label=_LABELS[score])
