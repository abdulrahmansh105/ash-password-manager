"""``ydotool``-backed input, for Wayland-wide synthetic input when no
structural (AT-SPI) target is available.

Requires ``ydotoold`` running and reachable (typically a systemd --user
service, with the invoking user in the ``input`` group and a udev rule
granting access to ``/dev/uinput`` -- NOT running as root; see
``docs/USB_SETUP.md`` / packaging for the exact one-time setup this
project's installer offers). ``password-manager doctor`` reports whether
``ydotoold`` is reachable without ever needing to type anything to check.

Security-critical detail: secret text is written to ``ydotool type``'s
stdin (``-f -``), never passed as an argv element, so it never appears in
``ps``/``/proc/<pid>/cmdline``. Key codes use the ``KEY_TAB``-style
integer namespace all synthetic Wayland input tools already share.
"""

from __future__ import annotations

import shutil
import subprocess
import time

from .backend import AuthInputBackend, BackendOutcome, InputResult

# Found live, not in unit tests: `ydotool type` and a subsequent
# `ydotool key` are two SEPARATE ydotoold client connections. ydotoold
# accepts the `type` command and returns control to the CLI (and hence
# to this process's subprocess.run()) once the events are *queued*, not
# once they've actually been drained to the virtual device -- so a next
# `ydotool key` call issued immediately after can race ahead and reach
# the focused field before all of the typed text has. Observed directly:
# without this settling delay, a 19-character username arrived as a
# single stray character in the field. 150ms was sufficient in testing
# against a real target app; kept small relative to typical per-step
# strategy timeouts (seconds) so it doesn't make autotype feel sluggish.
_TYPE_SETTLE_SECONDS = 0.15

# Linux input-event-codes.h keycodes (stable ABI, not going to change).
_KEYCODES = {
    "tab": 15,
    "enter": 28,
    "escape": 1,
    "ctrl": 29,
    "shift": 42,
    "alt": 56,
    "a": 30,
    "v": 47,
}


class YdotoolBackend(AuthInputBackend):
    name = "ydotool"

    def is_available(self) -> bool:
        if shutil.which("ydotool") is None:
            return False
        try:
            # `ydotool` talks to `ydotoold` over a unix socket; a no-op
            # key-list call is not available, so we just check the
            # daemon socket exists rather than sending any input.
            result = subprocess.run(
                ["pgrep", "-x", "ydotoold"], capture_output=True, timeout=2, check=False
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def type_text(self, secret: bytes) -> BackendOutcome:
        try:
            result = subprocess.run(
                ["ydotool", "type", "--key-delay", "12", "-f", "-"],
                input=secret,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return BackendOutcome(InputResult.FAILED, f"ydotool invocation error: {type(exc).__name__}")
        if result.returncode != 0:
            return BackendOutcome(InputResult.FAILED, "ydotool type exited non-zero")
        time.sleep(_TYPE_SETTLE_SECONDS)
        return BackendOutcome(InputResult.OK)

    def press_key(self, key: str) -> BackendOutcome:
        code = _KEYCODES.get(key.lower())
        if code is None:
            return BackendOutcome(InputResult.FAILED, f"unknown key name: {key}")
        return self._send_codes([code])

    def press_combo(self, combo: str) -> BackendOutcome:
        parts = [p.strip().lower() for p in combo.split("+")]
        codes = [_KEYCODES.get(p) for p in parts]
        if any(c is None for c in codes):
            return BackendOutcome(InputResult.FAILED, f"unknown key in combo: {combo}")
        # press all down, then release in reverse order
        seq = [f"{c}:1" for c in codes] + [f"{c}:0" for c in reversed(codes)]
        return self._send_raw(seq)

    def _send_codes(self, codes: list[int]) -> BackendOutcome:
        seq = [f"{c}:1" for c in codes] + [f"{c}:0" for c in codes]
        return self._send_raw(seq)

    def _send_raw(self, seq: list[str]) -> BackendOutcome:
        try:
            result = subprocess.run(
                ["ydotool", "key", *seq], capture_output=True, timeout=5, check=False
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return BackendOutcome(InputResult.FAILED, f"ydotool invocation error: {type(exc).__name__}")
        if result.returncode != 0:
            return BackendOutcome(InputResult.FAILED, "ydotool key exited non-zero")
        return BackendOutcome(InputResult.OK)
