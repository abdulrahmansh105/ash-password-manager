"""Exercise real GTK screens with synthetic metadata and isolated configuration."""
from types import SimpleNamespace
from uuid import uuid4

import pytest

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, Gtk

Gtk.init_check()
pytestmark = pytest.mark.skipif(Gdk.Display.get_default() is None, reason="GTK display unavailable")


@pytest.fixture
def ui_app(isolated_xdg, tmp_path):
    from passman.config.store import Settings, UsbRegistration
    from passman.core.security.memory import SecretBytes
    from passman.core.vault.models import AccountSecrets, AccountSummary

    app = Adw.Application(application_id=f"dev.ash.UiTest.t{uuid4().hex}", flags=Gio.ApplicationFlags.NON_UNIQUE)
    app.register()
    app.settings = Settings(theme="dark")
    summaries = [AccountSummary("one", "Example account", "Example", category="logins")]
    def secrets(_key):
        return AccountSecrets("one", "Example account", "Example", "demo@example.invalid", SecretBytes("synthetic-only"), "https://example.invalid", "Demo note", (), None, None)
    vault = SimpleNamespace(list_account_summaries=lambda: summaries, get_account_secrets=secrets, get_auth_strategy_json=lambda _: None)
    app.copied = []
    clipboard = SimpleNamespace(copy=lambda value, timeout: (app.copied.append((value, timeout)), SimpleNamespace(copied=True))[1])
    app.session = SimpleNamespace(vault=lambda: vault, is_unlocked=lambda: True, touch_activity=lambda: None, clipboard=clipboard)
    app.mountpoint = str(tmp_path)
    app.vault_id = ""
    app.registration = UsbRegistration(luks_uuid=None, filesystem_uuid="synthetic")
    app.detected_context = None
    yield app
    for window in list(app.get_windows()):
        window.destroy()


def test_manager_counts_categories_and_distinguishes_search_from_empty(ui_app):
    from passman.ui.manager.main_window import ManagerWindow
    window = ManagerWindow(ui_app)
    assert window._category_list.get_row_at_index(0).count.get_text() == "1"
    window._search_entry.set_text("unmatched")
    window._refresh_list()
    assert window._empty_status.get_title() == "No matching entries"
    window._on_empty_action(None)
    window._refresh_list()
    assert window._content_stack.get_visible_child_name() == "list"
    window._category_list.select_row(window._category_list.get_row_at_index(2))
    assert window._empty_status.get_title() == "This category is empty"
    window.destroy_sensitive_state()
    assert not window._all_summaries
    assert window._category_list.get_row_at_index(0).count.get_text() == "0"


@pytest.mark.parametrize("kind", ["entry", "detail", "generator", "totp", "recovery", "settings", "strategy", "picker", "locked"])
def test_all_screens_construct_with_real_gtk(ui_app, kind):
    from passman.ui.account_detail import AccountDetailDialog
    from passman.ui.entry_editor import EntryEditorDialog, RecoveryCodesDialog, TotpSetupDialog
    from passman.ui.generator_view import GeneratorDialog
    from passman.ui.launcher_window import AccountPickerWindow
    from passman.ui.locked_window import LockedWindow
    from passman.ui.manager.main_window import ManagerWindow
    from passman.ui.settings_window import SettingsDialog
    from passman.ui.strategy_editor import StrategyEditorDialog
    parent = ManagerWindow(ui_app)
    constructors = {
        "entry": lambda: EntryEditorDialog(ui_app, lambda: None),
        "detail": lambda: AccountDetailDialog(ui_app, "one", lambda: None),
        "generator": lambda: GeneratorDialog(parent),
        "totp": lambda: TotpSetupDialog(lambda _: None),
        "recovery": lambda: RecoveryCodesDialog(lambda _: None),
        "settings": lambda: SettingsDialog(ui_app),
        "strategy": lambda: StrategyEditorDialog(ui_app, "one", "Example", "Example", False, True, True, (), lambda: None),
        "picker": lambda: AccountPickerWindow(ui_app),
        "locked": lambda: LockedWindow(ui_app, "Insert your USB."),
    }
    screen = constructors[kind]()
    assert screen.has_css_class("pm-window")


def test_setup_has_no_continue_without_a_drive_and_keeps_progress_controlled(ui_app, monkeypatch):
    import passman.ui.setup.setup_window as mod
    monkeypatch.setattr(mod, "list_removable_drive_choices", lambda: [])
    window = mod.SetupWindow(ui_app)
    assert not window._usb_continue_btn.get_sensitive()
    assert window._usb_status_label.get_visible()
    page = window._build_progress_page("Creating your vault…")
    window._nav.push(page)
    assert not page.get_can_pop()
    assert window._nav.pop()  # worker completion can still pop programmatically


def test_login_disables_duplicate_submit_and_recovers_from_worker_error(ui_app, monkeypatch):
    import passman.ui.login.login_window as mod
    from passman.core.vaults.registry import VaultRecord
    monkeypatch.setattr(mod.LoginWindow, "_start_auto_login", lambda _: False)
    monkeypatch.setattr(mod.local_key_store, "has_local_key", lambda _: False)
    jobs = []
    monkeypatch.setattr(mod, "run_blocking_async", lambda *a, **kw: jobs.append((a, kw)))
    window = mod.LoginWindow(ui_app, VaultRecord(vault_id="fake", name="Demo", filesystem_uuid="fake"), ui_app.mountpoint)
    window._password_row.set_text("synthetic-password")
    window._on_submit_password(None)
    window._on_submit_password(None)
    assert len(jobs) == 1
    assert not window._login_btn.get_sensitive()
    assert window._login_btn.get_label() == "Unlocking…"
    jobs[0][1]["on_error"](OSError("must not expose this error detail"))
    assert window._login_btn.get_sensitive()
    assert not window._password_row.get_text()
    assert "must not expose" not in window._password_error.get_text()


def test_detail_copy_uses_session_clipboard_and_password_can_be_hidden_early(ui_app):
    from passman.ui.account_detail import AccountDetailDialog
    dialog = AccountDetailDialog(ui_app, "one", lambda: None)
    assert dialog._autotype_btn.get_label() == "Auto-Type"
    dialog._copy_field("password")
    assert ui_app.copied == [("synthetic-only", 30)]
    dialog._on_reveal_password(dialog._reveal_pw_btn)
    assert dialog._password_label.get_text() == "synthetic-only"
    dialog._on_reveal_password(dialog._reveal_pw_btn)
    assert dialog._password_label.get_text() == "••••••••"
    assert dialog._reveal_timer is None


def test_generator_starts_random_and_clears_inputs_on_close(ui_app):
    from passman.ui.generator_view import GeneratorDialog
    from passman.ui.manager.main_window import ManagerWindow
    dialog = GeneratorDialog(ManagerWindow(ui_app))
    assert dialog._stack.get_visible_child_name() == "random"
    for entry in dialog._sensitive_entries:
        entry.set_text("synthetic")
    dialog._on_closed(dialog)
    assert all(not entry.get_text() for entry in dialog._sensitive_entries)


def test_settings_apply_density_to_existing_windows(ui_app):
    from passman.ui.settings_window import SettingsDialog
    from passman.ui.manager.main_window import ManagerWindow
    window = ManagerWindow(ui_app)
    dialog = SettingsDialog(ui_app)
    dialog._density_row.set_selected(1)
    dialog._on_closed(dialog)
    assert window.has_css_class("pm-compact")
    dialog._density_row.set_selected(0)
    dialog._on_closed(dialog)
    assert not window.has_css_class("pm-compact")


def test_database_open_runs_in_worker_with_visible_progress(ui_app, monkeypatch):
    import passman.ui.login.login_window as mod
    from passman.core.security.memory import SecretBytes
    from passman.core.vaults.registry import VaultRecord
    monkeypatch.setattr(mod.LoginWindow, "_start_auto_login", lambda _: False)
    monkeypatch.setattr(mod.local_key_store, "has_local_key", lambda _: True)
    monkeypatch.setattr(mod, "touch_last_seen", lambda _: None)
    jobs, opened = [], []
    handle = object()
    monkeypatch.setattr(mod, "run_blocking_async", lambda *a, **kw: jobs.append((a, kw)))
    monkeypatch.setattr(mod, "open_vault", lambda *a: (opened.append(True), handle)[1])
    window = mod.LoginWindow(ui_app, VaultRecord(vault_id="fake", name="Demo", filesystem_uuid="fake"), ui_app.mountpoint)
    outcome = SimpleNamespace(vms=SecretBytes(b"x" * 32), used_local_key=True)
    window._finish_unlock(outcome)
    assert not opened
    assert window._stack.get_visible_child_name() == "checking"
    assert window._auth_busy
    work, done = jobs[0][0]
    done(work())
    assert opened == [True]
    assert window.result_handle is handle
