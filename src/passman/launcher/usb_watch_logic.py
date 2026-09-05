"""Pure edge-detection logic for the USB-watch agent (spec section 30):
which vaults just transitioned from "not connected" to "connected".
Kept separate from ``agent.py``'s D-Bus/subprocess I/O so it is
directly unit-testable, matching this project's established pattern
(``integration.logind``'s ``should_lock_on_sleep_signal`` and friends).
"""

from __future__ import annotations


def compute_newly_connected_vaults(previously_connected: set[str], currently_connected: set[str]) -> set[str]:
    """Edge-triggered: only vault ids present now but absent from the
    previous snapshot. A vault that was already connected on the last
    check (or that disconnects) never appears here -- this is what
    stops a burst of redundant UDisks2 signals for one physical
    insertion from spawning more than one sign-in attempt."""
    return currently_connected - previously_connected
