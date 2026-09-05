"""systemd-logind integration: screen-lock and suspend detection.

Verified live against this machine's system bus (session bus object
``org.freedesktop.login1.Session`` at the path for the current session
exposes a ``LockedHint`` property with ``emits-change``, and the Manager
object emits ``PrepareForSleep`` -- both confirmed present via
``busctl --system introspect`` before writing this module).

Decision logic is split out as pure functions so it's fully unit
testable against fabricated D-Bus payloads (spec requirement: mocked
signal/device events before any live/disruptive trigger) -- actually
subscribing to the bus is a thin wrapper around those.
"""

from __future__ import annotations

import os
from collections.abc import Callable

LOGIND_BUS_NAME = "org.freedesktop.login1"
LOGIND_MANAGER_PATH = "/org/freedesktop/login1"
LOGIND_MANAGER_IFACE = "org.freedesktop.login1.Manager"
LOGIND_SESSION_IFACE = "org.freedesktop.login1.Session"
PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"


def should_lock_on_sleep_signal(going_to_sleep: bool) -> bool:
    """``PrepareForSleep`` fires twice per suspend cycle: once with
    ``True`` just before sleeping, once with ``False`` on resume. Only
    the "about to sleep" edge should lock -- locking again on resume
    would be a no-op at best (session already locked) and is simply the
    wrong edge to act on."""
    return going_to_sleep


def should_lock_on_locked_hint_change(changed_properties: dict) -> bool:
    """``changed_properties`` is the dict from a
    ``org.freedesktop.DBus.Properties.PropertiesChanged`` signal on the
    session object. Only reacts to ``LockedHint`` actually becoming
    True; absent or False (e.g. some unrelated property changed, or the
    session unlocked) must not trigger a lock."""
    return changed_properties.get("LockedHint") is True


class LogindWatcher:
    """Thin GLib/Gio wrapper around the two pure functions above.
    Constructed and started only from the GTK main-loop process (the
    unlocked UI); never touches vault state itself -- callers pass an
    ``on_sleep``/``on_screen_locked`` callback (wired to
    ``Session.lock(...)`` in ``ui/app.py``)."""

    def __init__(
        self,
        on_sleep: Callable[[], None],
        on_screen_locked: Callable[[], None],
    ) -> None:
        self._on_sleep = on_sleep
        self._on_screen_locked = on_screen_locked
        self._connection = None
        self._subscription_ids: list[int] = []

    def start(self) -> bool:
        """Returns False (never raises) if the system bus or logind
        isn't reachable -- callers should treat that as "this trigger
        just isn't available on this system" rather than a fatal error;
        USB-removal and inactivity locking are unaffected either way."""
        try:
            import gi

            gi.require_version("Gio", "2.0")
            from gi.repository import Gio
        except Exception:  # noqa: BLE001
            return False

        try:
            self._connection = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            session_path = _current_session_path(self._connection, Gio)
        except Exception:  # noqa: BLE001
            return False

        sleep_id = self._connection.signal_subscribe(
            LOGIND_BUS_NAME,
            LOGIND_MANAGER_IFACE,
            "PrepareForSleep",
            LOGIND_MANAGER_PATH,
            None,
            Gio.DBusSignalFlags.NONE,
            self._on_prepare_for_sleep,
        )
        self._subscription_ids.append(sleep_id)

        if session_path is not None:
            lock_id = self._connection.signal_subscribe(
                LOGIND_BUS_NAME,
                PROPERTIES_IFACE,
                "PropertiesChanged",
                session_path,
                LOGIND_SESSION_IFACE,
                Gio.DBusSignalFlags.NONE,
                self._on_properties_changed,
            )
            self._subscription_ids.append(lock_id)
        return True

    def _on_prepare_for_sleep(self, _conn, _sender, _path, _iface, _signal, params) -> None:
        going_to_sleep = bool(params.unpack()[0])
        if should_lock_on_sleep_signal(going_to_sleep):
            self._on_sleep()

    def _on_properties_changed(self, _conn, _sender, _path, _iface, _signal, params) -> None:
        _iface_name, changed, _invalidated = params.unpack()
        if should_lock_on_locked_hint_change(changed):
            self._on_screen_locked()

    def stop(self) -> None:
        if self._connection is not None:
            for sub_id in self._subscription_ids:
                self._connection.signal_unsubscribe(sub_id)
        self._subscription_ids = []


def _current_session_path(connection, gio_module):
    session_id = os.environ.get("XDG_SESSION_ID")
    if not session_id:
        return None
    result = connection.call_sync(
        LOGIND_BUS_NAME,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_IFACE,
        "GetSession",
        gio_module.Variant("(s)", (session_id,)),
        gio_module.VariantType("(o)"),
        gio_module.DBusCallFlags.NONE,
        2000,
        None,
    )
    return result.unpack()[0]
