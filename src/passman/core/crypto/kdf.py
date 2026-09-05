"""Key-derivation primitives for the vault credential layer.

Two KDFs, two different jobs:

  * Argon2id -- turns the user's master PASSWORD into a key-encryption
    key (KEK). Deliberately slow and memory-hard: this is the one
    place a guessing attacker who has the USB has to spend real,
    tunable work. See ``docs/SECURITY.md`` for why this -- not the
    KDBX file's own KDF -- is the vault's actual guessing barrier.

  * HKDF-SHA256 -- turns an already-high-entropy secret (a 256-bit
    Local Key, optionally combined with a secret-store pepper) into a
    KEK. Deliberately fast: the input is already uniform random, so
    there is nothing to slow down for. What limits an attacker who
    only copied the Local Key *file* is the device-binding value mixed
    into the HKDF `info` parameter (see ``core.crypto.binding``), not
    KDF cost.

No custom cryptography: Argon2id via ``argon2-cffi``
(``argon2.low_level``), HKDF via a direct RFC 5869 implementation on
stdlib ``hmac``/``hashlib`` (small enough that pulling in a third
dependency for it would be the opposite of minimizing surface).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from ..security.memory import SecretBytes

KEY_LEN = 32  # 256-bit KEK, matching AES-256-GCM

# Argon2id cost parameters for the master-password slot, deliberately
# heavier than pykeepass's own inherited KDBX default (t=14 "rounds"
# but only 64 MiB memory -- see core/vault/kdbx.py's
# _upgrade_kdf_to_argon2id docstring). Tunable per slot (stored
# alongside the salt in the slot itself), so raising these later never
# invalidates an existing vault -- only new/changed password slots use
# the new numbers.
ARGON2ID_TIME_COST = 4
ARGON2ID_MEMORY_COST_KIB = 256 * 1024  # 256 MiB
ARGON2ID_PARALLELISM = 2
MIN_SALT_LEN = 16


@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = ARGON2ID_TIME_COST
    memory_cost_kib: int = ARGON2ID_MEMORY_COST_KIB
    parallelism: int = ARGON2ID_PARALLELISM

    def to_dict(self) -> dict[str, int]:
        return {
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
        }

    @staticmethod
    def from_dict(d: dict) -> "Argon2Params":
        return Argon2Params(
            time_cost=int(d["time_cost"]),
            memory_cost_kib=int(d["memory_cost_kib"]),
            parallelism=int(d["parallelism"]),
        )


# A deliberately cheap parameter set for tests only -- real vaults
# must never use this. Kept here (not duplicated per test file) so
# there is exactly one "this is the insecure test-speed preset" to
# audit.
INSECURE_FAST_PARAMS_FOR_TESTS_ONLY = Argon2Params(time_cost=1, memory_cost_kib=8 * 1024, parallelism=1)


def derive_key_argon2id(password: SecretBytes, salt: bytes, params: Argon2Params) -> bytes:
    """Derive a 256-bit KEK from a master password. Never logs the
    password and never returns it; the caller retains ownership of
    wiping ``password`` (this function only reads it)."""
    if len(salt) < MIN_SALT_LEN:
        raise ValueError(f"Argon2id salt must be at least {MIN_SALT_LEN} bytes.")
    pw_bytes = password.to_bytes()
    try:
        return hash_secret_raw(
            secret=pw_bytes,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost_kib,
            parallelism=params.parallelism,
            hash_len=KEY_LEN,
            type=Type.ID,
        )
    finally:
        del pw_bytes  # best-effort only; see core.security.memory's documented limitation


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract-then-expand)."""
    if length > 255 * hashlib.sha256().digest_size:
        raise ValueError("Requested HKDF output length is too large.")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]
