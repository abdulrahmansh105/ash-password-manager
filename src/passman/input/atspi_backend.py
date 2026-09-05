"""AT-SPI2 input backend: sets field content directly via the
accessibility tree instead of injecting global keystrokes.

Preferred over ydotool whenever available (see ``core.auth.engine``'s
backend selection), because it targets the actual focused editable
accessible object rather than "whatever currently has keyboard focus on
the whole desktop" -- meaningfully safer against wrong-window mistakes,
and works correctly for apps that mangle fast synthetic keystrokes.

Honest limitation: this module is written against the documented
``Atspi`` GObject-Introspection API, but has not been exercised against a
live accessibility bus in this environment (no display here). Every
call is wrapped so a missing/renamed API surface degrades to
``is_available() -> False`` rather than raising into caller code --
verify against your real session with ``password-manager doctor`` and
real target apps before relying on it; ``ydotool`` remains the
always-available fallback.
"""

from __future__ import annotations

from .backend import AuthInputBackend, BackendOutcome, InputResult

try:
    import gi

    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi  # type: ignore

    _ATSPI_IMPORT_OK = True
except Exception:  # noqa: BLE001 - any GI/import failure means "unavailable"
    Atspi = None  # type: ignore
    _ATSPI_IMPORT_OK = False


_EDITABLE_ROLES = {"entry", "text", "password text"}


class AtspiBackend(AuthInputBackend):
    name = "atspi"

    def is_available(self) -> bool:
        if not _ATSPI_IMPORT_OK:
            return False
        try:
            focused = self._get_focused_editable()
            return focused is not None
        except Exception:  # noqa: BLE001
            return False

    def _get_focused_editable(self):
        try:
            desktop = Atspi.get_desktop(0)
        except Exception:  # noqa: BLE001
            return None
        for i in range(desktop.get_child_count()):
            app = desktop.get_child_at_index(i)
            try:
                obj = self._find_focused(app)
            except Exception:  # noqa: BLE001
                obj = None
            if obj is not None:
                return obj
        return None

    def _find_focused(self, accessible, depth: int = 0):
        if depth > 12 or accessible is None:
            return None
        try:
            state_set = accessible.get_state_set()
            if state_set.contains(Atspi.StateType.FOCUSED):
                role = (accessible.get_role_name() or "").lower()
                if role in _EDITABLE_ROLES or accessible.get_editable_state():
                    return accessible
        except Exception:  # noqa: BLE001
            pass
        try:
            n = accessible.get_child_count()
        except Exception:  # noqa: BLE001
            return None
        for i in range(n):
            try:
                child = accessible.get_child_at_index(i)
            except Exception:  # noqa: BLE001
                continue
            found = self._find_focused(child, depth + 1)
            if found is not None:
                return found
        return None

    def type_text(self, secret: bytes) -> BackendOutcome:
        obj = self._get_focused_editable()
        if obj is None:
            return BackendOutcome(InputResult.UNAVAILABLE, "no focused editable accessible found")
        try:
            editable = obj.get_editable_text_iface()
            text_len = obj.get_character_count()
            editable.set_text_contents(secret.decode("utf-8"))
            del text_len
            return BackendOutcome(InputResult.OK)
        except Exception:  # noqa: BLE001
            return BackendOutcome(InputResult.FAILED, "AT-SPI set_text_contents failed")

    def press_key(self, key: str) -> BackendOutcome:
        # AT-SPI has no generic "press Tab in the focused widget" action
        # that works uniformly across toolkits; navigation keys are left
        # to the ydotool backend even when AT-SPI handled the text entry.
        return BackendOutcome(InputResult.UNAVAILABLE, "navigation keys not handled by AT-SPI backend")

    def press_combo(self, combo: str) -> BackendOutcome:
        return BackendOutcome(InputResult.UNAVAILABLE, "key combos not handled by AT-SPI backend")

    def focus_field(self, hint: str | None) -> BackendOutcome:
        # A precise "find the field whose accessible name/role matches
        # `hint`" search is app-specific enough that it is not
        # implemented generically here; this backend acts on whatever is
        # already focused (the strategy executor is expected to have
        # navigated there via Tab first, or the app opened with focus
        # already on the right field, which is the common case).
        return BackendOutcome(InputResult.UNAVAILABLE, "field-hint targeting not implemented")
