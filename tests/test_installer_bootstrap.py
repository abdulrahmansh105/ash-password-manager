"""Tests for installer/bootstrap.py -- the consent-based USB install
script (spec section 18). ``installer/`` is intentionally not part of
the ``passman`` package (see ``installer/__init__.py``), so this file
adds the project root to ``sys.path`` directly."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from installer import bootstrap  # noqa: E402


def test_default_scope_is_never_system(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    assert bootstrap.ask_scope_choice() == "user"


def test_explicit_system_choice_is_honored(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "2")
    assert bootstrap.ask_scope_choice() == "system"


def test_terminal_consent_declined_by_default(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    assert bootstrap._ask_consent_terminal() is False


def test_terminal_consent_accepted_on_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    assert bootstrap._ask_consent_terminal() is True


def test_find_bundled_wheel_none_when_absent(monkeypatch, tmp_path):
    fake_file = tmp_path / "bootstrap.py"
    fake_file.write_text("# placeholder")
    monkeypatch.setattr(bootstrap, "__file__", str(fake_file))
    assert bootstrap._find_bundled_wheel() is None


def test_find_bundled_wheel_finds_the_newest(monkeypatch, tmp_path):
    fake_file = tmp_path / "bootstrap.py"
    fake_file.write_text("# placeholder")
    (tmp_path / "ash_password_manager-0.1.0-py3-none-any.whl").write_text("x")
    (tmp_path / "ash_password_manager-0.2.0-py3-none-any.whl").write_text("x")
    monkeypatch.setattr(bootstrap, "__file__", str(fake_file))

    found = bootstrap._find_bundled_wheel()
    assert found is not None
    assert found.name == "ash_password_manager-0.2.0-py3-none-any.whl"


class _FakeResult:
    def __init__(self, returncode: int):
        self.returncode = returncode


def test_install_user_scope_prefers_pipx_and_never_calls_sudo(monkeypatch):
    calls = []
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/pipx" if name == "pipx" else None)
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda cmd, **kw: (calls.append(cmd), _FakeResult(0))[1])

    assert bootstrap.install_user_scope(None) is True
    assert calls == [["pipx", "install", bootstrap.PACKAGE_NAME]]
    assert not any("sudo" in str(arg) for call in calls for arg in call)


def test_install_user_scope_falls_back_to_pip_when_pipx_fails(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return _FakeResult(1 if cmd[0] == "pipx" else 0)

    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/pipx" if name == "pipx" else None)
    monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)

    assert bootstrap.install_user_scope(None) is True
    assert calls[0][0] == "pipx"
    assert "pip" in calls[1]
    assert "--user" in calls[1]


def test_install_user_scope_uses_bundled_wheel_path_when_given(monkeypatch, tmp_path):
    wheel = tmp_path / "ash_password_manager-0.2.0-py3-none-any.whl"
    wheel.write_text("x")
    calls = []
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/pipx" if name == "pipx" else None)
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda cmd, **kw: (calls.append(cmd), _FakeResult(0))[1])

    assert bootstrap.install_user_scope(wheel) is True
    assert calls == [["pipx", "install", str(wheel)]]


def test_install_system_scope_never_invokes_sudo_or_pkexec(monkeypatch, tmp_path):
    """This project's own code must never invoke sudo/pkexec itself --
    if makepkg needs root, that prompt comes from pacman/polkit, not
    from code here. Behavioral, not a source-text grep: records every
    subprocess.run call install_system_scope() actually makes."""
    pkgbuild_dir = tmp_path / "packaging" / "arch"
    pkgbuild_dir.mkdir(parents=True)
    (pkgbuild_dir / "PKGBUILD").write_text("# fake")
    fake_file = tmp_path / "installer" / "bootstrap.py"
    fake_file.parent.mkdir()
    fake_file.write_text("# placeholder")
    monkeypatch.setattr(bootstrap, "__file__", str(fake_file))

    calls = []
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/makepkg" if name == "makepkg" else None)
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda cmd, **kw: (calls.append(cmd), _FakeResult(0))[1])

    bootstrap.install_system_scope()

    assert calls, "install_system_scope() should have invoked makepkg"
    for call in calls:
        assert "sudo" not in call
        assert "pkexec" not in call


def test_install_system_scope_without_makepkg_fails_cleanly(monkeypatch):
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: None)
    assert bootstrap.install_system_scope() is False


def test_main_declines_cleanly_without_installing(monkeypatch):
    monkeypatch.setattr(bootstrap, "ask_consent", lambda: False)
    install_calls = []
    monkeypatch.setattr(bootstrap, "install_user_scope", lambda *_a, **_k: install_calls.append(1) or True)
    monkeypatch.setattr(bootstrap, "install_system_scope", lambda: install_calls.append(1) or True)

    assert bootstrap.main([]) == 0
    assert install_calls == []


def test_main_yes_flag_skips_consent_prompt_and_defaults_to_user_scope(monkeypatch):
    monkeypatch.setattr(bootstrap, "install_user_scope", lambda *_a, **_k: True)
    monkeypatch.setattr(bootstrap, "launch_app", lambda: None)
    consent_calls = []
    monkeypatch.setattr(bootstrap, "ask_consent", lambda: consent_calls.append(1) or True)

    assert bootstrap.main(["--yes"]) == 0
    assert consent_calls == []  # --yes must skip the prompt entirely
