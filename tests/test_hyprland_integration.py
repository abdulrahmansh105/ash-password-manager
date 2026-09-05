from __future__ import annotations

import json

from passman.integration.hyprland import keybind


class _FakeResult:
    """Minimal stand-in for subprocess.CompletedProcess -- this
    project's existing hand-rolled-fakes idiom, not unittest.mock."""

    def __init__(self, returncode: int, stdout: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout


def test_write_persistent_include_contains_bind_and_float_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    path = keybind.write_persistent_include("password-manager show")
    content = path.read_text(encoding="utf-8")

    assert "bind = SUPER CTRL, A, exec, password-manager show" in content
    assert f"windowrule = float, class:^({keybind.MAIN_APP_CLASS})$" in content
    assert f"windowrule = float, class:^({keybind.LOCKED_APP_CLASS})$" in content
    # Modern unified syntax only -- never the deprecated windowrulev2 name.
    assert "windowrulev2" not in content


def test_write_persistent_include_never_contains_a_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    path = keybind.write_persistent_include("password-manager show")
    content = path.read_text(encoding="utf-8")
    # "password" itself is expected (it's part of the app/command name,
    # e.g. "password-manager show") -- what must never appear is
    # anything secret-shaped: a TOTP/key/vault reference or value.
    for forbidden in ("totp", "secret", "key.key", "kdbx", "luks"):
        assert forbidden not in content.lower()


def test_source_line_points_at_the_written_file(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    path = keybind.write_persistent_include("password-manager show")
    assert keybind.source_line_for(path) == f"source = {path}"


def test_write_persistent_include_never_touches_hyprland_conf(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    hypr_dir = tmp_path / "hypr"
    hypr_dir.mkdir()
    real_config = hypr_dir / "hyprland.conf"
    real_config.write_text("# user's real config\nbind = SUPER, Q, exec, kitty\n", encoding="utf-8")

    keybind.write_persistent_include("password-manager show")

    assert real_config.read_text(encoding="utf-8") == "# user's real config\nbind = SUPER, Q, exec, kitty\n"


def test_register_runtime_bind_returns_false_when_hyprctl_unavailable(monkeypatch):
    monkeypatch.setattr(keybind.shutil, "which", lambda _n: None)
    assert keybind.register_runtime_bind("password-manager show") is False


# -- Current-Hyprland (>= ~0.5x) runtime bind via `hyprctl eval` -----------
#
# The classic `hyprctl keyword bind "MODS,KEY,exec,CMD"` mechanism was
# confirmed live, on this project's own development machine (Hyprland
# 0.56.2), to exit 0 and print "keyword can't work with non-legacy
# parsers. Use eval." without registering anything at all -- a real,
# version-drift regression, not a hypothetical. These tests cover the
# replacement mechanism (`hyprctl eval "hl.bind(...)"`) and, critically,
# that a lying exit code can never be trusted again the way it was here.


def test_register_runtime_bind_succeeds_on_current_hyprland(monkeypatch):
    monkeypatch.setattr(keybind.shutil, "which", lambda _n: "/usr/bin/hyprctl")
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if "eval" in args:
            assert "hl.bind(" in args[-1]
            assert "hl.dsp.exec_cmd(" in args[-1]
            assert "CTRL+ALT+P" in args[-1]
            return _FakeResult(0, b"ok")
        if "binds" in args:
            return _FakeResult(0, json.dumps([{"key": "P", "modmask": 12}]).encode())
        raise AssertionError(f"unexpected hyprctl invocation: {args}")

    monkeypatch.setattr(keybind.subprocess, "run", fake_run)
    assert keybind.register_runtime_bind("ash-password-manager sign-in", mods="CTRL ALT", key="P") is True
    # Both the eval and the follow-up verification query must actually run.
    assert any("eval" in c for c in calls)
    assert any("binds" in c for c in calls)


def test_register_runtime_bind_fails_when_eval_reports_an_error(monkeypatch):
    """A genuine rejection (confirmed live: an invalid dispatcher or an
    unparseable key string both produce exit code 7 with an "error:
    ..." line) must be reported as failure, and must never even reach
    the verification query."""
    monkeypatch.setattr(keybind.shutil, "which", lambda _n: "/usr/bin/hyprctl")

    def fake_run(args, **kwargs):
        if "eval" in args:
            return _FakeResult(7, b"error: hl.bind: failed to parse key string: Unknown keysym")
        raise AssertionError("binds -j must not be queried once eval itself already failed")

    monkeypatch.setattr(keybind.subprocess, "run", fake_run)
    assert keybind.register_runtime_bind("ash-password-manager sign-in", mods="CTRL ALT", key="P") is False


def test_register_runtime_bind_rejects_a_false_success_exit_code(monkeypatch):
    """The exact shape of the bug this replaces: a command that exits 0
    (and here even claims "ok") but the compositor's own live bind
    table shows nothing was actually registered. Trusting the exit
    code alone -- what the old `hyprctl keyword bind` mechanism forced
    this project into -- must never happen again."""
    monkeypatch.setattr(keybind.shutil, "which", lambda _n: "/usr/bin/hyprctl")

    def fake_run(args, **kwargs):
        if "eval" in args:
            return _FakeResult(0, b"ok")
        if "binds" in args:
            return _FakeResult(0, b"[]")  # nothing actually registered
        raise AssertionError(f"unexpected hyprctl invocation: {args}")

    monkeypatch.setattr(keybind.subprocess, "run", fake_run)
    assert keybind.register_runtime_bind("ash-password-manager sign-in", mods="CTRL ALT", key="P") is False


def test_register_runtime_bind_old_style_false_success_is_also_rejected(monkeypatch):
    """Belt-and-suspenders regression for the literal old failure
    shape: exit 0, but the printed text is not the expected "ok" (the
    real old message was "keyword can't work with non-legacy parsers.
    Use eval." -- any non-"ok" content on a 0 exit must fail closed)."""
    monkeypatch.setattr(keybind.shutil, "which", lambda _n: "/usr/bin/hyprctl")
    monkeypatch.setattr(
        keybind.subprocess, "run",
        lambda args, **kwargs: _FakeResult(0, b"keyword can't work with non-legacy parsers. Use eval."),
    )
    assert keybind._hyprctl_eval("hl.bind('P', hl.dsp.exec_cmd('x'))") is False


def test_bind_is_registered_matches_exact_modmask_and_key(monkeypatch):
    def fake_run(args, **kwargs):
        return _FakeResult(
            0,
            json.dumps([
                {"key": "P", "modmask": 4},  # CTRL only -- a different, unrelated bind
                {"key": "P", "modmask": 12},  # CTRL+ALT -- the one being looked for
            ]).encode(),
        )

    monkeypatch.setattr(keybind.subprocess, "run", fake_run)
    assert keybind._bind_is_registered("CTRL ALT", "P") is True
    assert keybind._bind_is_registered("SUPER", "P") is False


def test_register_runtime_bind_handles_a_bare_key_with_no_modifiers(monkeypatch):
    monkeypatch.setattr(keybind.shutil, "which", lambda _n: "/usr/bin/hyprctl")

    def fake_run(args, **kwargs):
        if "eval" in args:
            assert "'F12'" in args[-1]  # combo string must be the bare key, no leading "+"
            return _FakeResult(0, b"ok")
        if "binds" in args:
            return _FakeResult(0, json.dumps([{"key": "F12", "modmask": 0}]).encode())
        raise AssertionError(f"unexpected hyprctl invocation: {args}")

    monkeypatch.setattr(keybind.subprocess, "run", fake_run)
    assert keybind.register_runtime_bind("ash-password-manager sign-in", mods="", key="F12") is True
