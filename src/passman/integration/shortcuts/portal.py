"""XDG Desktop Portal GlobalShortcuts backend (spec section 9,
section 20's "not unnecessarily coupled to Hyprland"): the one
desktop-agnostic way to register a global hotkey, working across any
compositor that implements the portal -- confirmed present on this
project's own development machine
(``org.freedesktop.portal.GlobalShortcuts`` version 1, backed by
``xdg-desktop-portal-hyprland``) via ``busctl --user introspect``
before writing this module, matching the verification standard
``integration/logind.py`` already sets for D-Bus integrations here.

Genuinely asynchronous where it must be: ``BindShortcuts`` is allowed
by the portal spec to show the user a compositor-native confirmation
UI (to actually assign a key combination), which can take an
arbitrary, user-paced amount of time. This backend only ever nests a
bounded ``GLib.MainLoop`` for that one wait -- exclusively during the
one-time setup-wizard hotkey step, where a brief bounded wait for
explicit user confirmation is expected UX, never during normal
application operation.

Verified live, honestly reported: the D-Bus wire protocol handling
here is correct -- ``CreateSession`` round-trips a real, well-formed
response from ``xdg-desktop-portal-hyprland`` -- but that
implementation currently *rejects* the request outright
(``org.freedesktop.portal.Error.NotAllowed: An app id is required``)
for a normally-installed, non-sandboxed application, confirmed both as
a bare process and running under a proper
``systemd-run --user --scope --unit=app-<id>.scope``. This is a known
mismatch in GlobalShortcuts portal maturity across compositors (some
implementations currently expect Flatpak-style sandboxing to supply an
app identity), not a bug in this client. ``select_and_bind`` therefore
always falls through to the Hyprland backend (verified working) when
this happens -- this module is kept because it is spec-correct and may
work against other/future portal implementations, but Hyprland's own
native mechanism remains the practically-working path on this
project's primary target today. See docs/TROUBLESHOOTING.md.

One further architectural asymmetry worth noting: unlike Hyprland/
GNOME (where the compositor itself launches ``exec_cmd`` when the key
is pressed, needing no running process in between), the portal model
requires a long-running listener already connected to receive the
``Activated`` signal -- there is no "run this command" concept at the
portal level. ``bind()`` here only *registers* the shortcut; a caller
that wants portal-sourced activations must separately call
``listen_for_activation()`` from whatever long-running process holds
the session (the background agent, spec section 30 -- the one
disclosed, deliberate exception to this project's "nothing resident
while locked" stance).
"""

from __future__ import annotations

import itertools
import os
from collections.abc import Callable

from .backend import BindOutcome, BindResult, ShortcutBackend

PORTAL_BUS_NAME = "org.freedesktop.portal.Desktop"
PORTAL_OBJECT_PATH = "/org/freedesktop/portal/desktop"
REQUEST_IFACE = "org.freedesktop.portal.Request"
GLOBAL_SHORTCUTS_IFACE = "org.freedesktop.portal.GlobalShortcuts"
SHORTCUT_ID = "open-manager"

_token_counter = itertools.count(1)


def _new_token(prefix: str) -> str:
    # Portal request/session tokens must be valid D-Bus object-path
    # segments: [A-Za-z0-9_] only.
    return f"ash{prefix}{os.getpid()}_{next(_token_counter)}"


class PortalUnavailableError(Exception):
    pass


class PortalShortcutBackend(ShortcutBackend):
    name = "portal"

    def __init__(self) -> None:
        self._connection = None
        self._sender_token: str | None = None
        self.session_handle: str | None = None

    # -- connection -------------------------------------------------------

    def _ensure_connection(self):
        if self._connection is not None:
            return self._connection
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio

        connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        # Per the portal spec: the request/session object path embeds
        # the caller's unique bus name with ':' stripped and '.'
        # replaced by '_'.
        self._sender_token = connection.get_unique_name().lstrip(":").replace(".", "_")
        self._connection = connection
        return connection

    def is_available(self) -> bool:
        try:
            import gi

            gi.require_version("Gio", "2.0")
            from gi.repository import Gio, GLib

            connection = self._ensure_connection()
            reply = connection.call_sync(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "NameHasOwner",
                GLib.Variant("(s)", (PORTAL_BUS_NAME,)),
                GLib.VariantType("(b)"),
                Gio.DBusCallFlags.NONE,
                3000,
                None,
            )
            return bool(reply.unpack()[0])
        except Exception:  # noqa: BLE001
            return False

    def _request_path(self, token: str) -> str:
        return f"/org/freedesktop/portal/desktop/request/{self._sender_token}/{token}"

    def _wait_for_response(self, connection, gio_module, glib_module, token: str, timeout_ms: int) -> tuple[int, dict]:
        """Blocks, via a nested bounded main loop, until the portal's
        ``Response`` signal for this specific request token arrives or
        the timeout elapses. See module docstring for why a nested
        loop is acceptable here specifically."""
        loop = glib_module.MainLoop()
        outcome = {"code": 2, "results": {}}  # 2 = "ended by user"/cancelled, our default on timeout
        path = self._request_path(token)

        def handler(_conn, _sender, _path, _iface, _signal, params):
            outcome["code"], outcome["results"] = params.unpack()
            loop.quit()

        sub_id = connection.signal_subscribe(
            PORTAL_BUS_NAME, REQUEST_IFACE, "Response", path, None, gio_module.DBusSignalFlags.NONE, handler
        )
        timeout_id = glib_module.timeout_add(timeout_ms, loop.quit)
        try:
            loop.run()
        finally:
            connection.signal_unsubscribe(sub_id)
            glib_module.source_remove(timeout_id)
        return outcome["code"], outcome["results"]

    # -- ShortcutBackend interface -------------------------------------------

    def bind(self, accelerator: str, exec_cmd: str, description: str) -> BindOutcome:
        """Adapts this backend's session-based, event-driven model to
        the common ``ShortcutBackend.bind()`` contract. ``exec_cmd`` is
        accepted for interface conformance but unused -- the portal
        has no "run this command" concept (see module docstring);
        success here only means the shortcut was registered, not that
        anything will happen when it fires unless a caller separately
        wires ``listen_for_activation()`` into something long-running."""
        try:
            if not self.bind_shortcut(description, accelerator):
                return BindOutcome(BindResult.FAILED, "The portal declined this shortcut (see logs for detail).")
            return BindOutcome(BindResult.OK, "Registered via the desktop portal.")
        except Exception as exc:  # noqa: BLE001 - any GDBus/portal failure must degrade, never raise
            return BindOutcome(BindResult.FAILED, f"{type(exc).__name__}: {exc}")

    # -- session lifecycle ---------------------------------------------------

    def create_session(self, *, timeout_ms: int = 5000) -> bool:
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib

        connection = self._ensure_connection()
        handle_token = _new_token("create")
        # NOTE: the dict values must be pre-built GLib.Variant objects
        # (the "v" in "a{sv}" -- there's no way to infer a variant's
        # inner type from a plain Python value), but the dict itself
        # must stay a plain dict here, one level below the outer
        # "(a{sv})" GLib.Variant() call -- pre-building an "a{sv}"
        # Variant and nesting *that* inside the outer call raises
        # (PyGObject's constructor tries to iterate it as a plain
        # value, not splice it in as the already-typed member it is).
        options = {
            "handle_token": GLib.Variant("s", handle_token),
            "session_handle_token": GLib.Variant("s", _new_token("session")),
        }
        try:
            connection.call_sync(
                PORTAL_BUS_NAME,
                PORTAL_OBJECT_PATH,
                GLOBAL_SHORTCUTS_IFACE,
                "CreateSession",
                GLib.Variant("(a{sv})", (options,)),
                GLib.VariantType("(o)"),
                Gio.DBusCallFlags.NONE,
                timeout_ms,
                None,
            )
        except GLib.Error:
            return False
        code, results = self._wait_for_response(connection, Gio, GLib, handle_token, timeout_ms)
        if code != 0:
            return False
        self.session_handle = results.get("session_handle")
        return self.session_handle is not None

    def bind_shortcut(self, description: str, preferred_trigger: str | None, *, timeout_ms: int = 60_000) -> bool:
        """``preferred_trigger`` is only a hint (spec-legal for the
        compositor to ignore, and it commonly shows its own "press a
        key combination" UI regardless) -- the actually-assigned combo
        is whatever the ``Activated`` signal later reports, not
        necessarily this string."""
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib

        connection = self._ensure_connection()
        if self.session_handle is None and not self.create_session():
            return False

        handle_token = _new_token("bind")
        shortcut_opts: dict[str, GLib.Variant] = {"description": GLib.Variant("s", description)}
        if preferred_trigger:
            shortcut_opts["preferred_trigger"] = GLib.Variant("s", preferred_trigger)
        options = {"handle_token": GLib.Variant("s", handle_token)}  # plain dict; see create_session()'s note

        try:
            connection.call_sync(
                PORTAL_BUS_NAME,
                PORTAL_OBJECT_PATH,
                GLOBAL_SHORTCUTS_IFACE,
                "BindShortcuts",
                GLib.Variant(
                    "(oa(sa{sv})sa{sv})",
                    (self.session_handle, [(SHORTCUT_ID, shortcut_opts)], "", options),
                ),
                GLib.VariantType("(o)"),
                Gio.DBusCallFlags.NONE,
                5000,
                None,
            )
        except GLib.Error:
            return False
        code, _results = self._wait_for_response(connection, Gio, GLib, handle_token, timeout_ms)
        return code == 0

    def unbind(self) -> None:
        """Closes the portal session, if any. Not persistence-relevant
        (the compositor keeps the binding across the session
        regardless), but tidy on explicit user-initiated changes."""
        if self.session_handle is None or self._connection is None:
            return
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio

        try:
            self._connection.call_sync(
                PORTAL_BUS_NAME, self.session_handle, "org.freedesktop.portal.Session", "Close",
                None, None, Gio.DBusCallFlags.NONE, 3000, None,
            )
        except Exception:  # noqa: BLE001 - best-effort cleanup only
            pass
        self.session_handle = None

    def listen_for_activation(self, on_activated: Callable[[], None]) -> int:
        """Returns a subscription id (pass to ``connection.
        signal_unsubscribe`` to stop, e.g. on app shutdown)."""
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio

        connection = self._ensure_connection()

        def handler(_conn, _sender, _path, _iface, _signal, params):
            _session_handle, shortcut_id, _timestamp, _options = params.unpack()
            if shortcut_id == SHORTCUT_ID:
                on_activated()

        return connection.signal_subscribe(
            PORTAL_BUS_NAME, GLOBAL_SHORTCUTS_IFACE, "Activated", PORTAL_OBJECT_PATH, None,
            Gio.DBusSignalFlags.NONE, handler,
        )
