from __future__ import annotations

from passman.core.recovery.codes import RevealGate, deserialize, serialize
from passman.core.vault.models import RecoveryCode


def test_serialize_deserialize_round_trip():
    codes = [RecoveryCode(code="fake-aaaa1111", used=False), RecoveryCode(code="fake-bbbb2222", used=True)]
    raw = serialize(codes)
    back = deserialize(raw)
    assert [c.code for c in back] == [c.code for c in codes]
    assert [c.used for c in back] == [c.used for c in codes]


def test_deserialize_none_returns_empty():
    assert deserialize(None) == []


def test_deserialize_garbage_returns_empty():
    assert deserialize("not json") == []
    assert deserialize("[1, 2, 3]") == []


def test_reveal_gate_requires_request_before_confirm():
    gate = RevealGate(ttl_seconds=10)
    assert gate.confirm(now=100.0) is False


def test_reveal_gate_confirms_within_ttl():
    gate = RevealGate(ttl_seconds=10)
    gate.request(now=100.0)
    assert gate.confirm(now=105.0) is True


def test_reveal_gate_rejects_after_ttl_expired():
    gate = RevealGate(ttl_seconds=10)
    gate.request(now=100.0)
    assert gate.confirm(now=200.0) is False


def test_reveal_gate_is_single_use():
    gate = RevealGate(ttl_seconds=10)
    gate.request(now=100.0)
    assert gate.confirm(now=101.0) is True
    assert gate.confirm(now=101.5) is False  # second confirm without a new request fails
