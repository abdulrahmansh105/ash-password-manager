"""Recovery and failure-path regressions. All vaults and secrets are synthetic."""

from __future__ import annotations

import base64
import io
import json
import os
import shutil
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from passman.core.backup import archive
from passman.core.crypto.aead import seal
from passman.core.crypto.kdf import INSECURE_FAST_PARAMS_FOR_TESTS_ONLY as FAST
from passman.core.crypto.kdf import Argon2Params, derive_key_argon2id
from passman.core.crypto.keyslots import (
    KeySlot,
    SlotFormatError,
    SlotUnwrapError,
    vms_to_kdbx_password,
)
from passman.core.devices.registry import change_master_password, unlock_with_password
from passman.core.security.memory import SecretBytes
from passman.core.vault.kdbx import (
    VaultConflictError,
    VaultError,
    create_vault,
    open_vault,
)
from passman.core.vault.models import RecoveryCode
from passman.core.vault.provisioning import create_new_vault
from passman.core.vaults.layout import VaultLayout


def _open(layout, master):
    with unlock_with_password(layout, SecretBytes(master)) as vms:
        return open_vault(
            layout.kdbx_path,
            layout.keyfile_path,
            SecretBytes(vms_to_kdbx_password(vms)),
        )


def _bundle(path, entries, *, version=2):
    """Build authenticated deliberately malformed archives for adversarial tests."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = "../../outside"
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    salt = b"s" * 16
    with SecretBytes("backup-password") as pw:
        key = derive_key_argon2id(pw, salt, FAST)
    box = seal(key, buffer.getvalue(), aad=f"ash-pm/backup/v{version}".encode())
    header = json.dumps(
        {
            "version": version,
            "argon2": FAST.to_dict(),
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "nonce": base64.urlsafe_b64encode(box.nonce).decode(),
            "tag": base64.urlsafe_b64encode(box.tag).decode(),
        }
    ).encode()
    path.write_bytes(len(header).to_bytes(4, "big") + header + box.ciphertext)
    return path


@pytest.fixture
def managed_vault(fake_usb, isolated_xdg, no_secret_service):
    return create_new_vault(
        str(fake_usb),
        "ASH",
        "Synthetic",
        SecretBytes("original-master"),
        enroll_local_key=False,
        argon2_params=FAST,
    ).layout


def test_real_backup_restores_all_features_after_source_is_lost(
    managed_vault, tmp_path
):
    from passman.core.totp.totp import TotpConfig, generate_totp

    source = managed_vault
    handle = _open(source, "original-master")
    entry_id = handle.create_account(
        "Example",
        "Synthetic",
        "test-user",
        "test-password",
        url="https://example.invalid",
        notes="private note",
        tags=["work"],
        app_identifiers=["example", "re:^Example$"],
        auth_strategy_json='{"name":"test","steps":[]}',
        category="software",
    )
    handle.set_totp(entry_id, TotpConfig("JBSWY3DPEHPK3PXP"))
    handle.set_recovery_codes(entry_id, [RecoveryCode("fake-recovery", used=True)])
    handle.save()
    handle.close()
    backup = archive.create_backup(
        source, tmp_path / "safe.ashbak", SecretBytes("backup-password"), params=FAST
    )
    assert archive.verify_backup(backup, SecretBytes("backup-password"))
    assert b"test-password" not in backup.read_bytes()
    change_master_password(
        source, SecretBytes("original-master"), SecretBytes("later-master"), params=FAST
    )
    shutil.rmtree(source.container_dir)  # synthetic source USB lost
    destination = VaultLayout(tmp_path / "replacement" / "ASH")
    archive.restore_backup(backup, destination, SecretBytes("backup-password"))
    assert not list(destination.keyslots_dir.glob("device-*.slot"))
    with pytest.raises(SlotUnwrapError):
        unlock_with_password(destination, SecretBytes("later-master"))
    restored = _open(destination, "original-master")
    summary = restored.list_account_summaries()[0]
    assert summary.category == "software" and summary.tags == ("work",)
    with restored.get_account_secrets(entry_id) as account:
        assert account.password.to_str() == "test-password"
        assert account.username == "test-user" and account.notes == "private note"
        assert account.url == "https://example.invalid"
        assert account.app_identifiers == ("example", "re:^Example$")
        assert account.auth_strategy_json == '{"name":"test","steps":[]}'
        assert (
            account.recovery_codes[0].code == "fake-recovery"
            and account.recovery_codes[0].used
        )
        assert generate_totp(account.totp, at_time=59)
    restored.close()
    assert destination.keyslot_path("password").stat().st_mode & 0o777 == 0o600


def test_legacy_backup_requires_surviving_slot_and_then_actually_opens(
    managed_vault, tmp_path
):
    source = managed_vault
    entries = [
        (name, (source.container_dir / name).read_bytes(), tarfile.REGTYPE)
        for name in archive._LEGACY_NAMES
    ]
    legacy = _bundle(tmp_path / "old.ashbak", entries, version=1)
    destination = VaultLayout(tmp_path / "restored")
    with pytest.raises(archive.BackupError, match="not independently recoverable"):
        archive.verify_backup(legacy, SecretBytes("backup-password"))
    with pytest.raises(archive.BackupError, match="legacy-password-slot"):
        archive.restore_backup(legacy, destination, SecretBytes("backup-password"))
    assert not destination.container_dir.exists()
    archive.restore_backup(
        legacy,
        destination,
        SecretBytes("backup-password"),
        legacy_password_slot=source.keyslot_path("password"),
    )
    _open(destination, "original-master").close()


@pytest.mark.parametrize(
    "bad_entries",
    [
        [],
        [("Passwords.kdbx", b"x", tarfile.REGTYPE)],
        [("Passwords.kdbx", b"x", tarfile.REGTYPE)] * 2,
        [("../../outside", b"x", tarfile.REGTYPE)],
        [("Passwords.kdbx", b"", tarfile.SYMTYPE)],
        [("Passwords.kdbx", b"", tarfile.LNKTYPE)],
    ],
)
def test_verify_and_restore_reject_malformed_authenticated_payloads(
    tmp_path, bad_entries
):
    backup = _bundle(tmp_path / "bad.ashbak", bad_entries)
    destination = VaultLayout(tmp_path / "dest")
    with pytest.raises(archive.BackupCorruptError):
        archive.verify_backup(backup, SecretBytes("backup-password"))
    with pytest.raises(archive.BackupCorruptError):
        archive.restore_backup(backup, destination, SecretBytes("backup-password"))
    assert not destination.container_dir.exists()
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize(
    "manifest",
    [
        [],
        None,
        1,
        {"version": 2, "argon2": []},
        {
            "version": 2,
            "argon2": {
                "time_cost": 10**12,
                "memory_cost_kib": 10**12,
                "parallelism": 1000,
            },
        },
    ],
)
def test_backup_rejects_bad_headers_before_native_kdf(tmp_path, monkeypatch, manifest):
    header = json.dumps(manifest).encode()
    path = tmp_path / "bad.ashbak"
    path.write_bytes(len(header).to_bytes(4, "big") + header + b"ciphertext")

    def forbidden(*args):
        pytest.fail("native KDF must not receive unvalidated parameters")

    monkeypatch.setattr(archive, "derive_key_argon2id", forbidden)
    with pytest.raises(archive.BackupCorruptError):
        archive.verify_backup(path, SecretBytes("password"))


@pytest.mark.parametrize(
    "values",
    [
        {"time_cost": 0},
        {"time_cost": 17},
        {"time_cost": True},
        {"time_cost": "4"},
        {"memory_cost_kib": 2**40},
        {"memory_cost_kib": -1},
        {"parallelism": 1000},
        {"memory_cost_kib": 8, "parallelism": 2},
    ],
)
def test_argon_parameters_reject_resource_exhaustion(values):
    with pytest.raises((ValueError, TypeError)):
        Argon2Params(**values)


@pytest.mark.parametrize("raw", [None, [], "bad", {}, {"version": True}])
def test_malformed_slot_is_a_controlled_error(raw):
    with pytest.raises(SlotFormatError):
        KeySlot.from_dict(raw)


def test_restore_is_transactional_when_publish_fails(
    managed_vault, tmp_path, monkeypatch
):
    backup = archive.create_backup(
        managed_vault, tmp_path / "backup.ashbak", SecretBytes("password"), params=FAST
    )
    destination = VaultLayout(tmp_path / "restored")
    real_replace = os.replace

    def fail_restore(src, dst):
        if Path(dst) == destination.container_dir:
            raise OSError("synthetic disk failure")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", fail_restore)
    with pytest.raises(archive.BackupError):
        archive.restore_backup(backup, destination, SecretBytes("password"))
    assert not destination.container_dir.exists()
    assert not list(tmp_path.glob(".restored.restore-*"))


def test_vault_rejects_stale_writer_without_losing_saved_entries(managed_vault):
    first, stale = (
        _open(managed_vault, "original-master"),
        _open(managed_vault, "original-master"),
    )
    first.create_account("Saved entry", "service", "user", "password")
    first.save()
    stale.create_account("Stale edit", "service", "user", "password")
    with pytest.raises(VaultConflictError):
        stale.save()
    assert [
        s.display_name
        for s in _open(managed_vault, "original-master").list_account_summaries()
    ] == ["Saved entry"]
    first.close()
    stale.close()


def test_vault_failed_save_leaves_original_openable(managed_vault, monkeypatch):
    handle = _open(managed_vault, "original-master")
    original = managed_vault.kdbx_path.read_bytes()

    def fail(fh):
        fh.write(b"partial write")
        raise OSError("synthetic write failure")

    monkeypatch.setattr(handle._kp, "save", fail)
    with pytest.raises(VaultError):
        handle.save()
    assert managed_vault.kdbx_path.read_bytes() == original
    _open(managed_vault, "original-master").close()
    assert not list(managed_vault.container_dir.glob("*.tmp"))
    handle.close()


def test_create_refuses_to_clobber_existing_vault_and_wipes_password(tmp_path):
    vault = tmp_path / "existing.kdbx"
    vault.write_bytes(b"valuable-original")
    password = SecretBytes("fake-password")
    with pytest.raises(VaultError, match="overwrite"):
        create_vault(vault, tmp_path / "Key.key", password)
    assert vault.read_bytes() == b"valuable-original" and not password
    assert not (tmp_path / "Key.key").exists()


def test_atomic_json_does_not_follow_predictable_temp_symlink(tmp_path):
    from passman.core.util.atomic_json import write_json_atomic

    target = tmp_path / "record.json"
    victim = tmp_path / "unrelated"
    victim.write_text("preserve me")
    old_temp = target.with_suffix(target.suffix + f".tmp-{os.getpid()}")
    old_temp.symlink_to(victim)
    write_json_atomic(target, {"value": "safe"})
    assert victim.read_text() == "preserve me"
    assert json.loads(target.read_text()) == {"value": "safe"}
    assert target.stat().st_mode & 0o777 == 0o600


def test_session_uses_elapsed_time_and_finishes_lock_on_clipboard_failure(monkeypatch):
    from passman.core.security.session import LockReason, Session

    ticks = iter([100.0, 111.0])
    monkeypatch.setattr(
        "passman.core.security.session.time.monotonic", lambda: next(ticks)
    )

    class BadClipboard:
        def clear_now(self):
            raise OSError("synthetic clipboard failure")

    closed, callbacks = [], []
    session = Session(inactivity_timeout_seconds=10, _clipboard=BadClipboard())
    session.set_on_lock(callbacks.append)
    session.unlock(SimpleNamespace(close=lambda: closed.append(True)))
    assert session.check_inactivity()
    assert closed == [True] and callbacks == [LockReason.INACTIVITY_TIMEOUT]


def test_partial_and_empty_window_patterns_never_bypass_confirmation():
    from passman.core.auth.detection import (
        Confidence,
        DetectedContext,
        match_confidence,
    )

    context = DetectedContext("fake-discord", "Sign in")
    assert match_confidence(context, ("discord",)) == Confidence.LOW
    assert match_confidence(context, ("", " ")) == Confidence.UNKNOWN


def test_clipboard_preserves_external_value_and_clears_only_owned_value(monkeypatch):
    from passman.core.security.clipboard import ClipboardManager

    manager = ClipboardManager()
    monkeypatch.setattr(manager, "is_available", lambda: True)
    copied, state = [], {"value": b""}

    def run(argv, input=None, **kwargs):
        copied.append(argv)
        if argv == ["wl-paste", "-n"]:
            return SimpleNamespace(returncode=0, stdout=state["value"])
        if input is not None:
            state["value"] = input
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("passman.core.security.clipboard.subprocess.run", run)
    manager.clear_now()
    assert copied == []
    assert manager.copy("fake-secret", None).copied
    assert copied[-1] == ["wl-copy", "--sensitive"]
    state["value"] = b"user copied this later"
    manager.clear_now()
    assert ["wl-copy", "--clear"] not in copied
    manager.copy("fake-secret", None)
    manager.clear_now()
    assert copied[-1] == ["wl-copy", "--clear"]


def test_invalid_stored_totp_does_not_break_account_view(managed_vault):
    handle = _open(managed_vault, "original-master")
    entry = handle.create_account("Example", "Example", "user", "fake-password")
    handle._find(entry).otp = "otpauth://totp/Test?secret=bad!!&period=0"
    with handle.get_account_secrets(entry) as account:
        assert account.totp is None
        assert account.password.to_str() == "fake-password"
    handle.close()


def test_local_key_adoption_copies_external_usb_key_into_managed_layout(
    fake_usb, isolated_xdg, no_secret_service
):
    from passman.core.vault.kdbx import generate_keyfile
    from passman.core.vault.provisioning import adopt_existing_vault
    from pykeepass import create_database

    source_key = fake_usb / "original.key"
    generate_keyfile(source_key)
    container = fake_usb / "Legacy"
    container.mkdir()
    kp = create_database(
        str(container / "Passwords.kdbx"), password="old", keyfile=str(source_key)
    )
    kp.add_entry(kp.root_group, title="Preserve", username="test", password="fake")
    kp.save()
    result = adopt_existing_vault(
        str(fake_usb),
        "Legacy",
        "Adopted",
        existing_password=SecretBytes("old"),
        existing_keyfile_rel_path="original.key",
        new_master_password=SecretBytes("new"),
        enroll_local_key=False,
        argon2_params=FAST,
    )
    assert source_key.read_bytes() == result.layout.keyfile_path.read_bytes()
    reopened = _open(result.layout, "new")
    assert reopened.list_account_summaries()[0].display_name == "Preserve"
    reopened.close()


def test_health_detects_deleted_device_slot_and_malformed_manifest(tmp_path):
    from passman.core.vaults.health import (
        HealthStatus,
        check_vault_health,
        update_integrity_manifest,
    )

    layout = VaultLayout(tmp_path / "ASH")
    layout.ensure_dirs()
    path = layout.keyslot_path("device-fake")
    path.write_text("synthetic slot")
    update_integrity_manifest(layout)
    path.unlink()
    check = next(
        c for c in check_vault_health(layout).checks if c.name == "Integrity manifest"
    )
    assert check.status is HealthStatus.WARNING and "device-fake" in check.detail
    layout.integrity_json.write_text("[]")
    check = next(
        c for c in check_vault_health(layout).checks if c.name == "Integrity manifest"
    )
    assert check.status is HealthStatus.WARNING


def test_symbol_exclusion_applies_to_required_character():
    from passman.core.generator.random_generator import (
        PolicyError,
        RandomPasswordPolicy,
        generate_random_password,
    )

    policy = RandomPasswordPolicy(
        length=1,
        use_lower=False,
        use_upper=False,
        use_digits=False,
        symbols="I!",
        exclude_ambiguous=True,
    )
    assert {generate_random_password(policy) for _ in range(50)} == {"!"}
    with pytest.raises(PolicyError):
        generate_random_password(RandomPasswordPolicy(use_symbols=True, symbols=""))


def test_totp_rfc6238_vector_and_epoch_window():
    from passman.core.totp.totp import TotpConfig, generate_totp, verify_totp

    # RFC 6238 SHA-1 vector uses this public ASCII seed.
    seed = base64.b32encode(b"12345678901234567890").decode()
    config = TotpConfig(seed, digits=8)
    assert generate_totp(config, at_time=59) == "94287082"
    code = generate_totp(config, at_time=0)
    assert verify_totp(config, code, at_time=0, window=1)


def test_login_cancellation_stops_further_input_and_wipes_secrets():
    from passman.core.auth.engine import LoginEngine, LoginOutcome, SafetyGuardMode
    from passman.core.auth.detection import DetectedContext
    from passman.core.auth.strategy import AuthStep, AuthStrategy, StepAction
    from passman.core.auth.test_run import build_fake_secrets
    from passman.input.backend import BackendOutcome, InputResult

    typed = []
    backend = SimpleNamespace(
        type_text=lambda value: (typed.append(value), BackendOutcome(InputResult.OK))[1]
    )
    account = build_fake_secrets("test", "Test", "Test", ("example",), False)
    strategy = AuthStrategy(
        (AuthStep(StepAction.TYPE_USERNAME), AuthStep(StepAction.TYPE_PASSWORD))
    )
    result = LoginEngine(backend).run(
        account,
        strategy,
        DetectedContext("example", "Example"),
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        is_cancelled=lambda: bool(typed),
    )
    assert result.outcome is LoginOutcome.FAILED and len(typed) == 1
    assert not account.password and account.username == ""


def test_login_aborts_when_target_changes_and_wipes_on_guard_failure():
    from passman.core.auth.engine import LoginEngine, LoginOutcome, SafetyGuardMode
    from passman.core.auth.detection import DetectedContext
    from passman.core.auth.strategy import PASSWORD_ONLY_STRATEGY
    from passman.core.auth.test_run import build_fake_secrets

    def forbidden(*args):
        pytest.fail("input must not be sent to a changed target")

    account = build_fake_secrets("test", "Test", "Test", ("example",), False)
    result = LoginEngine(SimpleNamespace(type_text=forbidden)).run(
        account,
        PASSWORD_ONLY_STRATEGY,
        DetectedContext("example", "Example"),
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        context_provider=lambda: DetectedContext("different-app", "Elsewhere"),
    )
    assert result.outcome is LoginOutcome.FAILED and not account.password
    account = build_fake_secrets("test", "Test", "Test", ("example",), False)
    result = LoginEngine(None).run(
        account,
        PASSWORD_ONLY_STRATEGY,
        DetectedContext(None, None),
        SafetyGuardMode.ALWAYS_CONFIRM,
    )
    assert result.outcome is LoginOutcome.NEEDS_CONFIRMATION and not account.password


def test_async_login_reports_backend_failure_instead_of_hanging():
    from passman.core.auth.async_login import run_login_async
    from passman.core.auth.detection import DetectedContext
    from passman.core.auth.engine import LoginOutcome, SafetyGuardMode
    from passman.core.auth.strategy import PASSWORD_ONLY_STRATEGY
    from passman.core.auth.test_run import build_fake_secrets

    def fail():
        raise RuntimeError("fake backend error")

    account = build_fake_secrets("test", "Test", "Test", ("example",), False)
    results = []
    worker = run_login_async(
        fail,
        account,
        PASSWORD_ONLY_STRATEGY,
        DetectedContext("example", None),
        SafetyGuardMode.AUTO_ON_HIGH_CONFIDENCE,
        True,
        results.append,
        idle_scheduler=lambda callback: callback(),
    )
    worker.join(5)
    assert not worker.is_alive() and results[0].outcome is LoginOutcome.FAILED
    assert not account.password


def test_atspi_writes_through_editable_interface_and_delegates_navigation(monkeypatch):
    from passman.input.atspi_backend import AtspiBackend
    from passman.input.backend import BackendOutcome, InputResult

    written, navigation = [], []
    editable = SimpleNamespace(
        set_text_contents=lambda value: (written.append(value), True)[1]
    )
    nav = SimpleNamespace(
        is_available=lambda: True,
        press_key=lambda key: (navigation.append(key), BackendOutcome(InputResult.OK))[
            1
        ],
        press_combo=lambda key: (
            navigation.append(key),
            BackendOutcome(InputResult.OK),
        )[1],
    )
    backend = AtspiBackend(nav)
    monkeypatch.setattr(
        backend,
        "_get_focused_editable",
        lambda: SimpleNamespace(get_editable_text_iface=lambda: editable),
    )
    assert backend.type_text(b"fake-password").result is InputResult.OK
    assert backend.press_key("tab").result is InputResult.OK
    assert backend.press_combo("ctrl+a").result is InputResult.OK
    assert written == ["fake-password"] and navigation == ["tab", "ctrl+a"]
    editable.set_text_contents = lambda value: False
    assert backend.type_text(b"fake-password").result is InputResult.FAILED


def test_adoption_preserves_unselected_existing_keyfile(
    fake_usb, isolated_xdg, no_secret_service
):
    from passman.core.vault.provisioning import ProvisioningError, adopt_existing_vault
    from pykeepass import create_database

    container = fake_usb / "Legacy"
    container.mkdir()
    db = container / "Passwords.kdbx"
    create_database(str(db), password="old")
    original = db.read_bytes()
    (container / "Key.key").write_bytes(b"preserve-unrelated-key")
    with pytest.raises(ProvisioningError):
        adopt_existing_vault(
            str(fake_usb),
            "Legacy",
            "Test",
            existing_password=SecretBytes("old"),
            existing_keyfile_rel_path=None,
            new_master_password=SecretBytes("new"),
            enroll_local_key=False,
            argon2_params=FAST,
        )
    assert (container / "Key.key").read_bytes() == b"preserve-unrelated-key"
    assert db.read_bytes() == original


def test_entry_editor_preserves_custom_targets_and_updates_website(
    managed_vault, monkeypatch
):
    from passman.ui.entry_editor import EntryEditorDialog
    from passman.core.vault.models import CATEGORY_CHOICES

    handle = _open(managed_vault, "original-master")
    entry_id = handle.create_account(
        "Before",
        "Service",
        "user",
        "fake-password",
        url="https://old.invalid",
        app_identifiers=["custom-class", "re:^Custom$"],
    )

    class Field:
        def __init__(self, value=""):
            self.value = value

        def get_text(self, *args):
            return self.value

        def set_text(self, value):
            self.value = value

        def get_buffer(self):
            return self

        def get_start_iter(self):
            return 0

        def get_end_iter(self):
            return len(self.value)

        def set_selected(self, value):
            self.value = value

        def get_selected(self):
            return self.value

    saved = []
    dialog = SimpleNamespace(
        _app=SimpleNamespace(session=SimpleNamespace(vault=lambda: handle)),
        _entry_uuid=entry_id,
        _name_row=Field(),
        _service_row=Field(),
        _username_row=Field(),
        _password_row=Field(),
        _url_row=Field(),
        _notes_view=Field(),
        _identifiers_view=Field(),
        _category_row=Field(),
        _totp_config=None,
        _recovery_codes=[],
        _on_saved=lambda: saved.append(True),
        close=lambda: None,
    )
    EntryEditorDialog._load_existing(dialog, entry_id, None)
    assert dialog._identifiers_view.value == "custom-class\nre:^Custom$"
    assert dialog._url_row.value == "https://old.invalid"
    dialog._name_row.set_text("After")
    dialog._url_row.set_text("https://new.invalid")
    EntryEditorDialog._on_save(dialog, None)
    with handle.get_account_secrets(entry_id) as account:
        assert account.display_name == "After" and account.url == "https://new.invalid"
        assert account.app_identifiers == ("custom-class", "re:^Custom$")
        assert account.category == CATEGORY_CHOICES[0]
    assert saved == [True]
    # A failed first save of a new account must retain its UUID for retry.
    dialog._entry_uuid = None
    dialog._name_row.set_text("New pending entry")
    errors = []
    dialog._save_error = SimpleNamespace(
        set_label=errors.append, set_visible=lambda value: None
    )
    original_save = handle.save

    def fail():
        raise VaultError("Synthetic disk failure")

    monkeypatch.setattr(handle, "save", fail)
    EntryEditorDialog._on_save(dialog, None)
    pending_id = dialog._entry_uuid
    assert pending_id and errors and len(handle.list_account_summaries()) == 2
    monkeypatch.setattr(handle, "save", original_save)
    EntryEditorDialog._on_save(dialog, None)
    assert (
        dialog._entry_uuid == pending_id and len(handle.list_account_summaries()) == 2
    )
    assert saved == [True, True]
    handle.close()


def test_clipboard_fallback_uses_session_owner_and_honors_timeout(monkeypatch):
    from passman.core.security.session import LockReason, Session
    from passman.input import select_backend
    from passman.input.atspi_backend import AtspiBackend
    from passman.input.backend import BackendOutcome, InputResult
    from passman.input.clipboard_backend import ClipboardPasteBackend
    from passman.input.ydotool_backend import YdotoolBackend

    calls, cleared = [], []
    shared = SimpleNamespace(
        copy=lambda text, seconds: (
            calls.append((text, seconds)),
            SimpleNamespace(copied=True),
        )[1],
        clear_now=lambda: cleared.append(True),
    )
    session = Session(_clipboard=shared)
    monkeypatch.setattr(AtspiBackend, "is_available", lambda self: False)
    monkeypatch.setattr(YdotoolBackend, "is_available", lambda self: False)
    monkeypatch.setattr(ClipboardPasteBackend, "is_available", lambda self: True)
    backend = select_backend(True, clipboard=session.clipboard, clear_after_seconds=15)
    monkeypatch.setattr(
        backend._paste_key_backend,
        "press_combo",
        lambda combo: BackendOutcome(InputResult.OK),
    )
    assert backend.type_text(b"fake-password").result is InputResult.OK
    assert calls == [("fake-password", 15)]
    session.unlock(SimpleNamespace(close=lambda: None))
    session.lock(LockReason.MANUAL_CLOSE)
    assert cleared == [True]
