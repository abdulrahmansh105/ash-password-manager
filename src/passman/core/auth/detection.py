"""Local-only active-window detection and account-match confidence.

No browser extension, no network. Detection is a plain shell-out to
``hyprctl activewindow -j`` (Hyprland's own IPC, JSON output) -- this is
exactly the kind of "known application identifier" inspection spec
section 29 asks for, and it degrades safely: if hyprctl is unavailable
or returns nothing, detection simply reports "unknown", which the Safety
Guard (``core.auth.engine``) always treats as requiring confirmation.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class DetectedContext:
    app_id: str | None  # window class, e.g. "discord", "firefox"
    window_title: str | None


class Confidence(Enum):
    HIGH = "high"
    LOW = "low"
    UNKNOWN = "unknown"


def get_active_window_context() -> DetectedContext:
    """Best-effort active window lookup via Hyprland IPC. Never raises;
    returns an all-``None`` context on any failure so callers always fall
    back to the safe (confirm-required) path."""
    if shutil.which("hyprctl") is None:
        return DetectedContext(app_id=None, window_title=None)
    try:
        result = subprocess.run(
            ["hyprctl", "activewindow", "-j"],
            capture_output=True,
            timeout=2,
            check=False,
        )
        data = json.loads(result.stdout.decode("utf-8", errors="replace"))
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError, ValueError):
        return DetectedContext(app_id=None, window_title=None)
    app_id = data.get("class") or None
    title = data.get("title") or None
    return DetectedContext(app_id=app_id, window_title=title)


def match_confidence(context: DetectedContext, app_identifiers: tuple[str, ...]) -> Confidence:
    """Score how well ``context`` matches an account's configured
    ``app_identifiers`` (each entry is a case-insensitive substring or a
    ``re:`` prefixed regex, matched against both window class and title).

    - HIGH: an identifier matches the window class exactly (case-insensitive)
      -- the strongest, least ambiguous signal (window class is a stable
      app identity, unlike a title which changes per page/tab).
    - LOW: an identifier matches only the window title (substring/regex) --
      real (e.g. a browser tab title containing "Discord"), but title text
      is attacker/page-controlled, so it never reaches HIGH by itself.
    - UNKNOWN: no configured identifier matches anything, or detection
      itself failed (no window info at all).
    """
    if not app_identifiers or (context.app_id is None and context.window_title is None):
        return Confidence.UNKNOWN

    def _matches(pattern: str, value: str) -> bool:
        if pattern.startswith("re:"):
            try:
                return re.search(pattern[3:], value, re.IGNORECASE) is not None
            except re.error:
                return False
        return pattern.lower() in value.lower()

    if context.app_id:
        for pat in app_identifiers:
            if _matches(pat, context.app_id):
                return Confidence.HIGH

    if context.window_title:
        for pat in app_identifiers:
            if _matches(pat, context.window_title):
                return Confidence.LOW

    return Confidence.UNKNOWN
