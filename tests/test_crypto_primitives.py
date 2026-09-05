"""Tests for core.crypto.kdf, core.crypto.aead, core.crypto.binding --
the low-level primitives the key-slot format (test_keyslots.py) builds
on."""

from __future__ import annotations

import dataclasses

import pytest

from passman.core.crypto.aead import AeadError, open_box, seal
from passman.core.crypto.binding import BindingInput, compute_binding
from passman.core.crypto.kdf import Argon2Params, derive_key_argon2id, hkdf_sha256
from passman.core.security.memory import SecretBytes

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost_kib=8 * 1024, parallelism=1)


def test_argon2id_is_deterministic_for_same_inputs():
    salt = b"0" * 16
    key1 = derive_key_argon2id(SecretBytes("correct horse battery staple"), salt, FAST_PARAMS)
    key2 = derive_key_argon2id(SecretBytes("correct horse battery staple"), salt, FAST_PARAMS)
    assert key1 == key2
    assert len(key1) == 32


def test_argon2id_differs_for_different_passwords():
    salt = b"0" * 16
    key1 = derive_key_argon2id(SecretBytes("password-one"), salt, FAST_PARAMS)
    key2 = derive_key_argon2id(SecretBytes("password-two"), salt, FAST_PARAMS)
    assert key1 != key2


def test_argon2id_differs_for_different_salts():
    key1 = derive_key_argon2id(SecretBytes("same-password"), b"0" * 16, FAST_PARAMS)
    key2 = derive_key_argon2id(SecretBytes("same-password"), b"1" * 16, FAST_PARAMS)
    assert key1 != key2


def test_argon2id_rejects_short_salt():
    with pytest.raises(ValueError):
        derive_key_argon2id(SecretBytes("x"), b"short", FAST_PARAMS)


def test_hkdf_is_deterministic_and_length_correct():
    out1 = hkdf_sha256(b"input-key-material", b"salt", b"info")
    out2 = hkdf_sha256(b"input-key-material", b"salt", b"info")
    assert out1 == out2
    assert len(out1) == 32


def test_hkdf_differs_for_different_info():
    out1 = hkdf_sha256(b"ikm", b"salt", b"info-a")
    out2 = hkdf_sha256(b"ikm", b"salt", b"info-b")
    assert out1 != out2


def test_hkdf_differs_for_different_salt():
    out1 = hkdf_sha256(b"ikm", b"salt-a", b"info")
    out2 = hkdf_sha256(b"ikm", b"salt-b", b"info")
    assert out1 != out2


def test_hkdf_supports_custom_length():
    out = hkdf_sha256(b"ikm", b"salt", b"info", length=64)
    assert len(out) == 64


def test_aead_round_trip():
    key = b"k" * 32
    box = seal(key, b"secret payload", aad=b"context")
    assert open_box(key, box, aad=b"context") == b"secret payload"


def test_aead_rejects_wrong_key():
    box = seal(b"k" * 32, b"payload")
    with pytest.raises(AeadError):
        open_box(b"x" * 32, box)


def test_aead_rejects_tampered_ciphertext():
    key = b"k" * 32
    box = seal(key, b"payload")
    flipped = bytes([box.ciphertext[0] ^ 1]) + box.ciphertext[1:]
    with pytest.raises(AeadError):
        open_box(key, dataclasses.replace(box, ciphertext=flipped))


def test_aead_rejects_tampered_nonce():
    key = b"k" * 32
    box = seal(key, b"payload")
    flipped = bytes([box.nonce[0] ^ 1]) + box.nonce[1:]
    with pytest.raises(AeadError):
        open_box(key, dataclasses.replace(box, nonce=flipped))


def test_aead_rejects_tampered_tag():
    key = b"k" * 32
    box = seal(key, b"payload")
    flipped = bytes([box.tag[0] ^ 1]) + box.tag[1:]
    with pytest.raises(AeadError):
        open_box(key, dataclasses.replace(box, tag=flipped))


def test_aead_rejects_tampered_aad():
    key = b"k" * 32
    box = seal(key, b"payload", aad=b"correct-context")
    with pytest.raises(AeadError):
        open_box(key, box, aad=b"wrong-context")


def test_aead_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        seal(b"too-short", b"payload")


def test_aead_ciphertext_differs_across_calls_same_input():
    # Nonce must be fresh every time -- same plaintext/key must not
    # produce the same ciphertext twice.
    box1 = seal(b"k" * 32, b"payload")
    box2 = seal(b"k" * 32, b"payload")
    assert box1.nonce != box2.nonce
    assert box1.ciphertext != box2.ciphertext


def test_binding_is_stable_across_calls():
    assert compute_binding() == compute_binding()


def test_binding_changes_with_different_input_set():
    full = compute_binding((BindingInput.MACHINE_ID, BindingInput.UID, BindingInput.USERNAME))
    partial = compute_binding((BindingInput.UID,))
    assert full != partial


def test_binding_uid_only_is_stable():
    assert compute_binding((BindingInput.UID,)) == compute_binding((BindingInput.UID,))


def test_binding_changes_when_uid_changes(monkeypatch):
    monkeypatch.setattr("os.getuid", lambda: 1111)
    first = compute_binding((BindingInput.UID,))
    monkeypatch.setattr("os.getuid", lambda: 2222)
    second = compute_binding((BindingInput.UID,))
    assert first != second


def test_binding_changes_when_machine_id_changes(tmp_path, monkeypatch):
    machine_id_path = tmp_path / "machine-id"
    machine_id_path.write_text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
    monkeypatch.setattr("passman.core.crypto.binding._MACHINE_ID_PATHS", (machine_id_path,))
    first = compute_binding((BindingInput.MACHINE_ID,))

    machine_id_path.write_text("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")
    second = compute_binding((BindingInput.MACHINE_ID,))
    assert first != second


def test_binding_with_machine_id_unreadable_is_still_deterministic(monkeypatch):
    # No machine-id path is readable at all -- compute_binding must
    # still produce a stable, well-formed value (via the documented
    # "<absent>" marker) rather than raising or silently varying.
    monkeypatch.setattr("passman.core.crypto.binding._MACHINE_ID_PATHS", ())
    first = compute_binding((BindingInput.MACHINE_ID,))
    second = compute_binding((BindingInput.MACHINE_ID,))
    assert first == second
    assert len(first) == 32
