# Packaging

## The .run installer (the end-user install path)

`packaging/run-installer/` builds
`ASH-Password-Manager-Installer.run` -- a single self-extracting shell
script (built with `bash packaging/run-installer/build.sh`) that end
users download from GitHub Releases and run directly. It needs no git
clone, no `makepkg`, no `pipx`, no manually created virtual
environment, and no manually installed Python packages. See the
[README's Install section](../README.md#install) for what it does
from the user's side.

Internally it:

1. Builds the project wheel (same `pyproject.toml` as every other
   path below) and bundles it with `password-manager.desktop`, the
   icon, the systemd `--user` agent unit, and `install.sh`
   (`packaging/run-installer/install.sh`) into a gzipped tarball
   appended to `packaging/run-installer/stub.sh`.
2. At run time, the stub extracts that tarball to a temp directory and
   hands off to `install.sh`, which asks for consent, creates a
   per-user virtual environment with `python -m venv
   --system-site-packages` (this is what correctly sidesteps Arch's
   PEP 668 externally-managed-environment restriction -- a venv is
   exempt from it, no `--break-system-packages` needed), `pip
   install`s the bundled wheel into it (pulling `pykeepass`,
   `argon2-cffi`, `pycryptodomex` from PyPI as normal), symlinks the
   three entry points into `~/.local/bin`, installs the desktop entry
   and icon, offers the optional background agent, and verifies
   itself with `ash-password-manager version` / `ashpm version` before
   launching `sign-in`.
3. Detects an existing install (a manifest file under
   `~/.local/share/ash-password-manager/`) and asks Update/Reinstall
   instead of silently overwriting it; `--uninstall` (optionally
   `--purge`) reverses everything it added, without ever touching a
   vault, `.kdbx`, `Key.key`, or device slot.

Rebuild it with:

```bash
bash packaging/run-installer/build.sh
```

which writes `dist/ASH-Password-Manager-Installer.run` and a
version-suffixed copy for GitHub Releases
(`dist/ASH-Password-Manager-<version>-Arch-<arch>.run`); it refuses to
build if it finds any vault/personal-data pattern in the payload. The
`.run` file itself is a build artifact -- like a wheel, it is never
committed to the repository; it is attached to GitHub Releases only.

## Other installation methods (developers, packagers, non-Arch)

### Arch Linux, via the raw PKGBUILD

`packaging/arch/PKGBUILD` is what the `.run` installer's wheel is
built from, and remains fully usable standalone if you'd rather have
pacman track the install -- it is not, itself, the end-user
distribution artifact:

```bash
cd packaging/arch
makepkg -si
```

Builds from the local source tree (`packaging/arch/PKGBUILD`'s
`prepare()` copies `src/`, `tests/`, `assets/`, and packaging metadata
into the build directory -- never a personal vault, because there
isn't one in the source tree to copy). Runs the full test suite as
part of `check()`. Installs:

- `ash-password-manager`, `ashpm`, `ash-password-manager-agent`,
  `password-manager`, `password-manager-launcher` (all point at the
  same code; the last two are kept for anyone already using the
  pre-rebrand names)
- `/usr/share/applications/dev.ash.PasswordManager.desktop`
- `/usr/share/icons/hicolor/scalable/apps/password-manager.svg`
- `/usr/lib/systemd/user/ash-password-manager-agent.service`
  (installed, **not** enabled -- see below)

Upgrade: bump `pkgver` in the PKGBUILD, re-run `makepkg -si` (standard
pacman upgrade flow). Uninstall: `sudo pacman -R ash-password-manager`.

### Anywhere else (pipx / pip)

Not published on PyPI yet -- install straight from GitHub:

```bash
pipx install "git+https://github.com/abdulrahmansh105/ash-password-manager.git" \
  --system-site-packages
```

or, from a built wheel:

```bash
python -m build --wheel
pipx install dist/ash_password_manager-*.whl
```

Requires the system packages `python-gobject`/`PyGObject`, GTK4, and
Libadwaita to already be present (these bind to the platform's native
GTK/Adwaita libraries and are not meaningfully installable via pip);
everything else (`pykeepass`, `argon2-cffi`, `pycryptodomex`) is a
normal Python dependency pulled in automatically.

Neither installation path installs, depends on, or requires
KeePassXC — see `docs/SECURITY.md`.

## The USB install bootstrap (`installer/bootstrap.py`)

A complete, tested, dependency-free (stdlib-only) consent-based
installer script -- see `docs/SECURITY.md` and spec section 18 for
what it must and must not do. The Arch package installs a copy at
`/usr/share/ash-password-manager/installer/bootstrap.py`; placing a
copy of it into a specific vault USB's `install/` directory is
currently a **manual** step:

```bash
cp /usr/share/ash-password-manager/installer/bootstrap.py /path/to/usb/install/
```

The setup wizard does not automate this copy yet. Doing so for a
`pip`/`pipx`-based (non-Arch) install would need a wheel-bundling
mechanism this project does not implement -- `bootstrap.py` can install
from a wheel placed alongside it (`ash_password_manager-*.whl` in the
same directory) if one is present, and otherwise falls back to
`pipx install ash-password-manager` / `pip install --user
ash-password-manager` against whatever package index is configured,
which requires the package to actually be published there.

## The optional background agent

Installed but not started automatically by the package. Enabling it
is an explicit choice, offered once during first-time setup (default
on) and always reversible:

```bash
systemctl --user enable --now ash-password-manager-agent.service
systemctl --user disable --now ash-password-manager-agent.service   # to turn it back off
```

See `packaging/systemd/README.md` for exactly what it does and does
not have access to.

## Development install

```bash
cd password-manager
python -m venv --system-site-packages .venv   # --system-site-packages: reuses the platform's PyGObject/GTK4
source .venv/bin/activate
pip install -e .
pip install pytest
python -m pytest -q
```

## Building a release artifact

```bash
python -m build --wheel
python -m zipfile -l dist/*.whl   # confirm before publishing -- see the checklist below
```

## Confirming the package is clean

Before any release, confirm the built artifact contains no personal
data (`docs/RELEASE_CHECKLIST.md` has the full list):

```bash
python -m zipfile -l dist/*.whl | grep -Ei '\.kdbx|\.key|\.slot|vault\.json|devices\.json|usb\.json'
# must print nothing
```
