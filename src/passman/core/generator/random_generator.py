"""Cryptographically random password generation.

New in the password manager (the original template generator is
deterministic by design and is preserved unchanged in ``template_engine``).
This mode exists for accounts where you want a truly random secret rather
than a memorable derived one, backed by the ``secrets`` module (CSPRNG),
never ``random``.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

_AMBIGUOUS = set("Il1O0")


@dataclass(frozen=True)
class RandomPasswordPolicy:
    length: int = 24
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    symbols: str = "!@#$%^&*()-_=+[]{};:,.?/"

    def alphabet(self) -> str:
        chars = ""
        if self.use_lower:
            chars += string.ascii_lowercase
        if self.use_upper:
            chars += string.ascii_uppercase
        if self.use_digits:
            chars += string.digits
        if self.use_symbols:
            chars += self.symbols
        if self.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in _AMBIGUOUS)
        return chars


class PolicyError(Exception):
    """Raised when a policy cannot produce any password (e.g. no
    character classes selected, or length too small to satisfy the
    at-least-one-per-class guarantee)."""


def generate_random_password(policy: RandomPasswordPolicy) -> str:
    """Generate a random password satisfying ``policy`` using ``secrets``.

    Guarantees at least one character from each selected class when the
    requested length allows it. Never falls back to the non-CSPRNG
    ``random`` module.
    """
    alphabet = policy.alphabet()
    if not alphabet:
        raise PolicyError("At least one character class must be enabled.")
    if policy.length < 1:
        raise PolicyError("Password length must be at least 1.")

    classes = []
    if policy.use_lower:
        classes.append([c for c in string.ascii_lowercase if not policy.exclude_ambiguous or c not in _AMBIGUOUS])
    if policy.use_upper:
        classes.append([c for c in string.ascii_uppercase if not policy.exclude_ambiguous or c not in _AMBIGUOUS])
    if policy.use_digits:
        classes.append([c for c in string.digits if not policy.exclude_ambiguous or c not in _AMBIGUOUS])
    if policy.use_symbols:
        classes.append(list(policy.symbols))

    if policy.length < len(classes):
        raise PolicyError(
            f"Password length {policy.length} is too short to include all "
            f"{len(classes)} selected character classes."
        )

    required = [secrets.choice(c) for c in classes if c]
    remaining = policy.length - len(required)
    rest = [secrets.choice(alphabet) for _ in range(remaining)]

    result = required + rest
    # Fisher-Yates shuffle using the CSPRNG (secrets has no shuffle()).
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]
    return "".join(result)
