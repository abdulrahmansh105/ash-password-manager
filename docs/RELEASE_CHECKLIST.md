# Release checklist

## Before every release

- [ ] `python -m pytest -q` -- full suite green (549+ tests at time of
      writing; `pytest --collect-only -q | tail -1` to confirm the
      current count).
- [ ] `git status` clean; nothing untracked that should be tracked (or
      vice versa).
- [ ] **No personal data anywhere in the tree that will be packaged.**
      Run:
      ```bash
      find . -not -path './.venv/*' -not -path './.git/*' \
        \( -name '*.kdbx' -o -name 'Key.key' -o -name 'ash-pass-manager.key' \
           -o -name '*.slot' -o -name '*.ashbak' -o -name 'vault.json' \
           -o -name 'devices.json' -o -name 'usb.json' \)
      ```
      Must print nothing except (if present) `demo/demo-vault/*`, which
      is fake data, already gitignored, and never packaged (see below).
- [ ] `python -m build --wheel && python -m zipfile -l dist/*.whl` --
      confirm the artifact contains only `src/passman/**`,
      `password_manager*.dist-info/**`, and no `demo/`, no vault files.
- [ ] `demo/create_demo_vault.py --overwrite` still runs and its
      round-trip assertions pass (validates the KDBX compatibility
      layer against the real, installed `pykeepass`).
- [ ] `tests/test_no_keepassxc_coupling.py` passes -- no KeePassXC
      binary/import reference, and `pykeepass` is the only vault
      dependency, in both `pyproject.toml` and `packaging/arch/PKGBUILD`.
- [ ] Version bumped consistently: `pyproject.toml`'s `[project]
      version`, `packaging/arch/PKGBUILD`'s `pkgver` (reset `pkgrel=1`
      on a version bump).
- [ ] `README.md`'s test count and CLI examples match reality.
- [ ] `docs/SECURITY.md` and `docs/THREAT_MODEL.md` still accurately
      describe the shipped behavior -- re-read them if any crypto,
      device-binding, or agent-related code changed since the last
      release; these documents make specific, falsifiable claims and
      must not silently drift from the code.

## Arch package

- [ ] `cd packaging/arch && makepkg -si` succeeds from a clean
      `src/`/`pkg/` (remove them first: `rm -rf src pkg *.pkg.tar.zst`).
- [ ] Installed `.desktop` file opens the app; the icon appears.
- [ ] `systemctl --user status ash-password-manager-agent.service`
      shows the unit is installed (not necessarily enabled).
- [ ] `pacman -Qi ash-password-manager` shows the expected version and
      dependencies (`python-argon2-cffi`, `python-pycryptodomex`
      included).

## The .run installer (the end-user install path)

- [ ] `bash packaging/run-installer/build.sh` succeeds and refuses to
      build if it finds any vault/personal-data pattern in the payload.
- [ ] In a scratch `$HOME` (never your real one): running the produced
      `dist/ASH-Password-Manager-Installer.run` with no arguments asks
      for consent and installs nothing if declined.
- [ ] `./*.run --yes --no-agent` installs cleanly, `ash-password-manager
      version` / `ashpm version` both succeed, the `.desktop` entry and
      icon exist, and `ash-password-manager sign-in` launches.
- [ ] Running it again against that same scratch `$HOME` detects the
      existing install and offers Update/Reinstall instead of silently
      overwriting it.
- [ ] `./*.run --uninstall` removes the venv, symlinks, desktop entry,
      icon, and systemd unit, but leaves any local settings/device
      Local Keys in place; `--uninstall --purge` removes those too.
      Neither ever touches a vault, `.kdbx`, `Key.key`, or slot.
- [ ] Rename `dist/ASH-Password-Manager-Installer.run` to
      `ASH-Password-Manager-X.Y.Z-Arch-x86_64.run` (or use the copy
      `build.sh` already produces) and attach it to the GitHub Release
      -- never commit the `.run` binary itself to the repository.

## Manual smoke test (see also the plan's own verification section)

- [ ] Fresh `ash-password-manager sign-in` against a **scratch** USB
      (never a real/personal one) completes the full wizard end to end.
- [ ] Relaunching with the Local Key enrolled shows **no password
      prompt**.
- [ ] Deleting the Local Key file and relaunching shows the password
      prompt exactly once, and succeeds.
- [ ] A second (simulated or real) device registers independently and
      gets a different `ash-pass-manager.key`.
- [ ] Revoking one device in Settings -> Devices does not affect the
      other.
- [ ] `backup create` then `backup verify` round-trips on the scratch
      vault.
- [ ] Pulling the scratch USB triggers a lock; plugging it back in
      (with the agent enabled) opens exactly one login window, not
      several.

## Publishing

- [ ] Tag the release in git (`git tag vX.Y.Z`) -- only after every box
      above is checked.
- [ ] Do not publish a wheel or package built from a working tree with
      uncommitted changes.
