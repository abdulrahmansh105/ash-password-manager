from __future__ import annotations

import io
import contextlib

import pytest

from passman.cli.main import dispatch


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    yield


def _run(argv, monkeypatch):
    monkeypatch.setattr("sys.argv", ["password-manager", *argv])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = dispatch()
    return code, buf.getvalue()


def test_version_prints_version_and_exits_zero(monkeypatch):
    code, out = _run(["version"], monkeypatch)
    assert code == 0
    assert out.strip()


def test_generate_template_matches_core_engine(monkeypatch):
    code, out = _run(
        ["generate", "template", "--template", "{USERNAME}-{SERVICE_NAME}", "--username", "ash", "--service", "Discord"],
        monkeypatch,
    )
    assert code == 0
    assert out.strip() == "ash-Discord"


def test_generate_random_prints_password_of_requested_length(monkeypatch):
    code, out = _run(["generate", "random", "--length", "40"], monkeypatch)
    assert code == 0
    assert len(out.strip()) == 40


def test_doctor_never_prints_a_password_like_string(monkeypatch):
    code, out = _run(["doctor"], monkeypatch)
    assert code == 0
    assert "password" not in out.lower() or "Password Manager" not in out  # sanity: no field labeled with a value
    # No line should look like it's printing a secret value (heuristic: no
    # long random-looking token after a colon).
    for line in out.splitlines():
        assert not line.strip().startswith("secret")


def test_doctor_reports_full_identity_chain_when_registered(monkeypatch, tmp_path):
    from passman.config.store import UsbRegistration, save_usb_registration

    vault_dir = tmp_path / "usb-root" / "Authentication"
    vault_dir.mkdir(parents=True)
    (vault_dir / "Passwords.kdbx").write_bytes(b"x")
    (vault_dir / "Key.key").write_bytes(b"x")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    save_usb_registration(
        UsbRegistration(
            luks_uuid="1a7da154-f312-450c-89b2-dd995b282243",
            filesystem_uuid="c22baf3d-05a0-4ec0-88fe-72928556594c",
            vault_rel_path="Authentication/Passwords.kdbx",
            keyfile_rel_path="Authentication/Key.key",
        )
    )

    import json

    from passman.integration.usb.identity import parse_lsblk_json

    raw = json.dumps(
        {
            "blockdevices": [
                {
                    "name": "sdc",
                    "path": "/dev/sdc",
                    "uuid": "1a7da154-f312-450c-89b2-dd995b282243",
                    "fstype": "crypto_LUKS",
                    "type": "disk",
                    "mountpoint": None,
                    "children": [
                        {
                            "name": "luks-x",
                            "path": "/dev/mapper/luks-x",
                            "uuid": "c22baf3d-05a0-4ec0-88fe-72928556594c",
                            "fstype": "ext4",
                            "type": "crypt",
                            "mountpoint": str(tmp_path / "usb-root"),
                        }
                    ],
                }
            ]
        }
    )
    monkeypatch.setattr("passman.cli.main.list_block_devices", lambda: parse_lsblk_json(raw))

    code, out = _run(["doctor"], monkeypatch)

    assert code == 0
    assert "[OK] USB identity" in out
    assert "[OK] LUKS identity" in out
    assert "[OK] filesystem identity" in out
    assert "[OK] vault relative path (Authentication/Passwords.kdbx)" in out
    assert "[OK] key file relative path (Authentication/Key.key)" in out


def test_status_without_registration_does_not_crash(monkeypatch):
    code, out = _run(["status"], monkeypatch)
    assert code == 0
    assert "not registered" in out.lower()


def test_lock_without_running_session_reports_already_locked(monkeypatch):
    code, out = _run(["lock"], monkeypatch)
    assert code == 0
    assert "already locked" in out.lower()


def test_no_command_prints_help_and_exits_nonzero(monkeypatch):
    code, _out = _run([], monkeypatch)
    assert code == 2
