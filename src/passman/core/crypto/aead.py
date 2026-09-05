"""AES-256-GCM authenticated encryption for wrapping the Vault Master
Secret inside a key slot.

Deliberately thin: ``pycryptodomex`` does the actual cryptography,
this module only fixes the nonce/tag sizes and turns every failure
mode (wrong key, tampered ciphertext, tampered nonce, tampered
authenticated-associated-data) into the same ``AeadError`` -- so a
caller can never accidentally distinguish "wrong key" from "tampered
data" from the exception type alone (spec section 21: never leak
whether a secret was partially correct).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from Cryptodome.Cipher import AES

NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32


class AeadError(Exception):
    """Raised on any seal/open failure. Never carries the attempted
    key, plaintext, or AAD in its message."""


@dataclass(frozen=True)
class SealedBox:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> SealedBox:
    if len(key) != KEY_LEN:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    nonce = secrets.token_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return SealedBox(nonce=nonce, ciphertext=ciphertext, tag=tag)


def open_box(key: bytes, box: SealedBox, aad: bytes = b"") -> bytes:
    if len(key) != KEY_LEN:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    if len(box.nonce) != NONCE_LEN or len(box.tag) != TAG_LEN:
        raise AeadError("Authentication failed -- malformed sealed box.")
    cipher = AES.new(key, AES.MODE_GCM, nonce=box.nonce, mac_len=TAG_LEN)
    if aad:
        cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(box.ciphertext, box.tag)
    except ValueError as exc:
        raise AeadError("Authentication failed -- wrong key or tampered data.") from exc
