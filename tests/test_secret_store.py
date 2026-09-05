"""Tests for core.devices.secret_store -- the optional Secret Service
pepper, and its graceful degradation when no Secret Service is
reachable (spec section 4). This project's own development machine has
the libsecret typelib available but no Secret Service daemon
activatable, so FILE_ONLY (forced deterministically here via the
``no_secret_service`` fixture) is the default-exercised path -- these
tests do not depend on any particular machine's D-Bus state."""

from __future__ import annotations

from passman.core.devices.secret_store import (
    ProtectionTier,
    is_available,
    provision_pepper,
    resolve_pepper,
)


def test_is_available_false_when_no_secret_service(no_secret_service):
    assert is_available() is False


def test_provision_pepper_falls_back_to_file_only(no_secret_service):
    result = provision_pepper("vault-1", "device-1")
    assert result.tier == ProtectionTier.FILE_ONLY
    assert result.pepper is None


def test_resolve_pepper_is_none_for_file_only_tier(no_secret_service):
    assert resolve_pepper("vault-1", "device-1", ProtectionTier.FILE_ONLY) is None


def test_resolve_pepper_returns_none_when_service_unreachable_even_if_tier_says_otherwise(no_secret_service):
    """A slot created when a Secret Service *was* reachable, opened
    later when it no longer is (service restarted without
    persistence, item deleted out-of-band, disabled...) must resolve
    to None -- never fabricate a substitute pepper."""
    assert resolve_pepper("vault-1", "device-1", ProtectionTier.SECRET_SERVICE) is None


class _FakeSchema:
    @staticmethod
    def new(name, flags, attr_types):
        return object()


class _FakeSecretModule:
    """Minimal stand-in for gi.repository.Secret, following this
    project's existing hand-rolled-fake test idiom (no unittest.mock).
    Stores items in a plain dict keyed by the attribute tuple."""

    SchemaAttributeType = type("AttrType", (), {"STRING": "string"})()
    SchemaFlags = type("Flags", (), {"NONE": 0})()
    COLLECTION_DEFAULT = "default"
    Schema = _FakeSchema

    def __init__(self):
        self._store: dict[tuple, str] = {}

    def _key(self, attributes: dict[str, str]) -> tuple:
        return tuple(sorted(attributes.items()))

    def password_store_sync(self, schema, attributes, collection, label, password, cancellable):
        self._store[self._key(attributes)] = password
        return True

    def password_lookup_sync(self, schema, attributes, cancellable):
        return self._store.get(self._key(attributes))

    def password_clear_sync(self, schema, attributes, cancellable):
        return self._store.pop(self._key(attributes), None) is not None


def test_provision_and_resolve_pepper_round_trip_with_fake_secret_service(monkeypatch):
    fake = _FakeSecretModule()
    monkeypatch.setattr("passman.core.devices.secret_store._try_import_secret", lambda: fake)

    result = provision_pepper("vault-1", "device-1")
    assert result.tier.value == "secret_service"
    assert result.pepper is not None

    resolved = resolve_pepper("vault-1", "device-1", result.tier)
    assert resolved is not None
    assert resolved.to_bytes() == result.pepper.to_bytes()


def test_different_devices_get_different_peppers(monkeypatch):
    fake = _FakeSecretModule()
    monkeypatch.setattr("passman.core.devices.secret_store._try_import_secret", lambda: fake)

    result_a = provision_pepper("vault-1", "device-a")
    result_b = provision_pepper("vault-1", "device-b")
    assert result_a.pepper.to_bytes() != result_b.pepper.to_bytes()
