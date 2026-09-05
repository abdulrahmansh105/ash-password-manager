#!/usr/bin/env python3
"""ASH Password Manager -- consent-based USB install bootstrap
(spec section 18).

This script is what may sit in the ``install/`` directory of an ASH
vault USB, entirely opt-in (the setup wizard asks before ever placing
it there; ``Settings.bootstrap_installer_enabled`` defaults to False).

Hard rules, enforced by this file's actual behavior, not just its
docstring:

  * It NEVER runs on its own just because the USB was connected --
    Linux does not autorun removable media, and this project does not
    pretend otherwise. A person has to open this file and run it.
  * It ALWAYS asks for explicit confirmation before doing anything,
    and exits cleanly (no partial state, nothing installed) if the
    user declines.
  * It defaults to an UNPRIVILEGED, per-user install (``pipx``, else
    ``pip install --user``) into the user's own ``~/.local/bin`` --
    no ``sudo``, no root, no writes outside the user's home.
  * A system-wide install is offered only as an explicit, separate
    choice the user must actively select -- and even then, this
    script never calls ``sudo``/``pkexec`` itself. If that path needs
    elevation, the elevation prompt comes from the OS's own tooling
    (``makepkg -si`` -> pacman -> polkit), never from code here.
  * It does no more than hand off to the standard installation methods
    documented in docs/PACKAGING.md -- it is a consent-gated launcher
    for those, never a second, separate install mechanism.

Deliberately dependency-free (stdlib only): this runs on a machine
that, by definition, does not have ASH Password Manager -- and quite
possibly not GTK4/PyGObject either -- installed yet.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

PACKAGE_NAME = "ash-password-manager"
LAUNCH_CMD = ["ash-password-manager", "sign-in"]

CONSENT_TITLE = "ASH Password Manager is not installed"
CONSENT_BODY = (
    "This USB contains an ASH Password Manager vault.\n\n"
    "Install ASH Password Manager on this device to access it?\n\n"
    "This installs for your user only (no administrator/root access), "
    "and does nothing until you confirm."
)


def _find_bundled_wheel() -> Path | None:
    here = Path(__file__).resolve().parent
    wheels = sorted(here.glob("ash_password_manager-*.whl"))
    return wheels[-1] if wheels else None


def _ask_consent_zenity() -> bool | None:
    if not shutil.which("zenity"):
        return None
    result = subprocess.run(
        ["zenity", "--question", "--title", CONSENT_TITLE, "--text", CONSENT_BODY,
         "--ok-label", "Install", "--cancel-label", "Cancel"],
        capture_output=True, timeout=300, check=False,
    )
    return result.returncode == 0


def _ask_consent_kdialog() -> bool | None:
    if not shutil.which("kdialog"):
        return None
    result = subprocess.run(
        ["kdialog", "--title", CONSENT_TITLE, "--yesno", CONSENT_BODY,
         "--yes-label", "Install", "--no-label", "Cancel"],
        capture_output=True, timeout=300, check=False,
    )
    return result.returncode == 0


def _ask_consent_terminal() -> bool:
    print(f"\n{CONSENT_TITLE}\n{'=' * len(CONSENT_TITLE)}\n")
    print(CONSENT_BODY)
    answer = input("\nInstall now? [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def ask_consent() -> bool:
    for method in (_ask_consent_zenity, _ask_consent_kdialog):
        result = method()
        if result is not None:
            return result
    return _ask_consent_terminal()


def ask_scope_choice() -> str:
    """Returns "user" (default, unprivileged) or "system" -- an
    explicit secondary choice, never the default."""
    print("\nInstall scope:")
    print("  [1] This user only (recommended -- no root, ~/.local/bin)")
    print("  [2] System-wide (uses your distro's package manager; may prompt for your password)")
    choice = input("Choose [1]: ").strip()
    return "system" if choice == "2" else "user"


def install_user_scope(wheel: Path | None) -> bool:
    target = str(wheel) if wheel is not None else PACKAGE_NAME
    if shutil.which("pipx"):
        result = subprocess.run(["pipx", "install", target], check=False)
        if result.returncode == 0:
            return True
        print("pipx install failed; trying pip --user instead.", file=sys.stderr)
    result = subprocess.run([sys.executable, "-m", "pip", "install", "--user", target], check=False)
    return result.returncode == 0


def install_system_scope() -> bool:
    """Never calls sudo/pkexec itself -- if makepkg needs root for
    pacman, that prompt comes from pacman/polkit directly, not from
    this script. Requires a source tree with packaging/arch/PKGBUILD
    alongside this script (e.g. a checked-out repo, not the bare
    bootstrap file alone) -- if that isn't present, this reports
    exactly that instead of guessing."""
    if not shutil.which("makepkg"):
        print(
            "System-wide install needs an Arch-based system with `makepkg`. "
            "See docs/PACKAGING.md, or choose the per-user install instead.",
            file=sys.stderr,
        )
        return False
    pkgbuild_dir = Path(__file__).resolve().parent.parent / "packaging" / "arch"
    if not (pkgbuild_dir / "PKGBUILD").exists():
        print(
            "No PKGBUILD found alongside this installer. System-wide install needs the "
            "full project source (see docs/PACKAGING.md); choose the per-user install instead.",
            file=sys.stderr,
        )
        return False
    result = subprocess.run(["makepkg", "-si"], cwd=pkgbuild_dir, check=False)
    return result.returncode == 0


def launch_app() -> None:
    local_bin = Path.home() / ".local" / "bin" / "ash-password-manager"
    cmd = LAUNCH_CMD if shutil.which("ash-password-manager") else [str(local_bin), "sign-in"]
    try:
        subprocess.Popen(cmd, start_new_session=True)
    except OSError as exc:
        print(f"Installed, but could not launch automatically ({exc}). Run: {' '.join(LAUNCH_CMD)}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--yes", action="store_true", help="Skip the interactive consent prompt (still never sudo).")
    parser.add_argument("--system", action="store_true", help="Install system-wide instead of per-user.")
    args = parser.parse_args(argv)

    if not args.yes and not ask_consent():
        print("Cancelled. Nothing was installed.")
        return 0

    scope = "system" if args.system else (ask_scope_choice() if not args.yes else "user")

    if scope == "system":
        ok = install_system_scope()
    else:
        ok = install_user_scope(_find_bundled_wheel())

    if not ok:
        print("Installation failed. See docs/PACKAGING.md for manual instructions.", file=sys.stderr)
        return 1

    print("[OK] ASH Password Manager installed.")
    launch_app()
    return 0


if __name__ == "__main__":
    sys.exit(main())
