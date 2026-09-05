from __future__ import annotations

from passman.launcher.usb_watch_logic import compute_newly_connected_vaults


def test_first_connection_is_newly_connected():
    assert compute_newly_connected_vaults(set(), {"v1"}) == {"v1"}


def test_already_connected_is_not_reported_again():
    assert compute_newly_connected_vaults({"v1"}, {"v1"}) == set()


def test_disconnection_reports_nothing():
    assert compute_newly_connected_vaults({"v1"}, set()) == set()


def test_multiple_vaults_only_new_one_reported():
    assert compute_newly_connected_vaults({"v1"}, {"v1", "v2"}) == {"v2"}


def test_burst_of_repeated_signals_reports_only_once():
    previously = set()
    currently = {"v1"}
    first = compute_newly_connected_vaults(previously, currently)
    assert first == {"v1"}
    # Simulate the agent updating its "previously connected" snapshot,
    # then a second, redundant signal for the same still-connected vault.
    second = compute_newly_connected_vaults(currently, currently)
    assert second == set()
