<p align="center">
  <img src="assets/icons/password-manager.svg" width="96" height="96" alt="ASH Password Manager icon">
</p>

<h1 align="center">ASH Password Manager</h1>

<p align="center">
  A USB-first, device-bound password manager for Linux desktops.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue.svg">
  <img alt="Platform: Linux / Wayland" src="https://img.shields.io/badge/platform-Linux%20%2F%20Wayland-informational">
  <img alt="Tests: 549 passing" src="https://img.shields.io/badge/tests-549%20passing-brightgreen">
</p>

Your vault lives on a USB drive you control; a master password protects
it everywhere, and an optional per-device **Local Key** lets a
specific computer unlock it without typing that password again --
without ever turning the Local Key into a portable credential.

```
USB connected, Local Key valid on this device -> Manager opens, no password asked
USB connected, no valid Local Key on this device -> Password -> Manager opens
                                                              -> offer to register this device
USB missing -> "Connect your ASH Password Manager USB to continue"
```

Everything runs offline. No cloud sync, no telemetry, no browser
extension, no network dependency for normal operation.

**This application does not include any personal password database.**
The public source and package ship no `Passwords.kdbx`, no `Key.key`,
no key slots, and no Local Key. You create your own vault, on your own
USB, during first-time setup -- see [Sign in](#sign-in--first-time-setup) below.

## Contents

- [The model, precisely](#the-model-precisely)
- [Sign in / first-time setup](#sign-in--first-time-setup)
- [Returning: Login](#returning-login)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Install](#install)
- [Install from a USB (consent-based only)](#install-from-a-usb-consent-based-only)
- [First run](#first-run)
- [CLI](#cli)
- [Testing](#testing)
- [Demo vault](#demo-vault)
- [Documentation](#documentation)
- [Known limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

## The model, precisely

```
USB Vault          = portable            -- carries no machine fingerprint
Local Key          = device-specific     -- copying the file to another device does nothing
Master Password    = universal fallback  -- always works, on any device, forever
USB registration    = device/app policy   -- which USB this app expects to see
KDBX encryption     = the actual vault cryptographic protection
```

Read [`docs/SECURITY.md`](docs/SECURITY.md) before relying on this for
anything real. It states plainly what is a cryptographic guarantee and
what is application policy, and does not claim more than either
actually provides.

## Sign in / first-time setup

```
Select your USB -> Create Password -> Create Local Key? (optional)
  -> Vault created, this device registered -> Choose Hotkey
  -> USB Removal Protection explained & configured -> Manager
```

A password-only vault is never enough on its own here: the master
password is wrapped once, Argon2id, into a `password.slot` on the USB.
Every registered device gets its **own** independent, device-bound
`device-<id>.slot` -- deleting one slot revokes exactly that device
and nothing else; changing the master password rewraps one small file
and every other device keeps working unchanged. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#credential-architecture)
for the exact construction.

If a USB already has a non-ASH KDBX on it, setup offers to **adopt**
it (keeping every existing entry) instead of starting over -- scoped
to the USB you just selected, never a generic "import any file" flow
(spec-mandated: this project deliberately has no such feature at all).

## Returning: Login

Connect the USB. If this device has a valid Local Key for that vault,
the manager opens with **no password prompt, ever** -- that is the one
hard product rule this whole design is built around. Any problem with
the Local Key (missing, corrupted, revoked, a different device
entirely) falls through to the password automatically, exactly once;
there is no path back to a login loop.

A successful password login on a device with no Local Key yet offers
to register that device and mint it a brand-new key -- never copied
from anywhere.

## Architecture

```
src/passman/
  core/
    crypto/           Argon2id + HKDF-SHA256 + AES-256-GCM key-slot format (docs/SECURITY.md)
    devices/          Local Key storage, libsecret pepper (optional), on-USB device registry
    vaults/           multi-vault local registry, traversal-safe on-USB layout, health checks
    vault/            KDBX compatibility layer (kdbx.py, unchanged) + provisioning.py (guarded
                       create / adopt-existing / rekey, all transactional)
    flows/            pure setup/login state machines + USB pick/unlock/mount orchestration
    backup/           encrypted backup/restore (never Local Keys or the master secret)
    accounts/         search + suggestion ranking over non-secret AccountSummary
    totp/             hand-rolled RFC 6238 (no third-party TOTP dependency)
    recovery/         recovery-code (de)serialization + explicit two-step reveal gate
    generator/        template_engine.py (ported from ptgen) + random_generator.py
    auth/             login-automation strategy model + executor + Safety Guard (advanced,
                       optional feature -- reachable from an entry's detail view and
                       Settings -> Authentication only, never the primary flow)
    security/         session/lock state machine, clipboard, SecretBytes, safe logging,
                       password-strength heuristic
  config/             non-secret local settings (~/.config/ash-password-manager)
  integration/
    usb/              UDisks2 GIR client (enumeration + hotplug) with an lsblk/udisksctl
                       fallback; pure USB-identity decision logic
    shortcuts/        XDG GlobalShortcuts portal, Hyprland, GNOME backends + Manual fallback
    hyprland/         hyprctl IPC (unchanged)
    logind/           screen-lock/suspend detection (unchanged)
    notify.py         best-effort notify-send wrapper (lock/device/backup events; never secrets)
  input/              AuthInputBackend abstraction: AT-SPI, ydotool, clipboard-paste (unchanged)
  ui/
    setup/            first-time setup wizard
    login/            the login popup
    manager/          the main, post-unlock password manager window
    theme.py          the white/blue ASH brand palette (opt-out to "Follow system")
    (existing: launcher_window.py, entry_editor.py, account_detail.py, generator_view.py,
     settings_window.py, locked_window.py, app.py -- all reused, not rewritten)
  launcher/           ash_daemon.py (new multi-vault entry point) + daemon.py (legacy,
                       unchanged) + agent.py (optional background USB-watch process) + ipc.py
  cli/                argparse CLI: sign-in/login/recover, devices, backup, agent, plus every
                       original subcommand, unchanged
installer/            consent-based USB bootstrap (never auto-runs; see spec section 18)
tests/                549 tests, fake data and synthetic fixtures only; several exercise the
                      real UDisks2/GlobalShortcuts-portal D-Bus services live where available
demo/                 create_demo_vault.py -- builds + validates a fully fake demo vault
docs/                 SECURITY, ARCHITECTURE, THREAT_MODEL, USB_SETUP, BACKUP_RECOVERY,
                      INPUT_BACKENDS, PACKAGING, CONFIGURATION, TROUBLESHOOTING,
                      RELEASE_CHECKLIST, MIGRATION
packaging/            Arch PKGBUILD, systemd --user unit for the optional agent, .desktop, icon
```

`core/` has zero GTK dependency -- every credential/vault/flow module
is independently unit-tested without a display.

## Requirements

- Linux, Wayland (Hyprland is the primary target; the architecture is
  not coupled to it -- see `integration/shortcuts/` and
  `docs/ARCHITECTURE.md`)
- `python` >= 3.11, `python-gobject`, `gtk4`, `libadwaita`
- `python-pykeepass`, `python-argon2-cffi`, `python-pycryptodomex`
- `udisks2`, `util-linux` (removable-media detection; `cryptsetup` if
  your vault USB uses LUKS -- optional, not required)
- optional: `ydotool`/`at-spi2-core` (autotype, an advanced feature),
  `zbar` (TOTP QR import), `xdg-desktop-portal` (cross-desktop
  global-shortcut support outside Hyprland)

## Install

**Arch Linux: download one file, run it.** No git clone, no `makepkg`,
no `pipx`, no manually created virtual environment, no manually
installed Python packages.

1. Download the latest `ASH-Password-Manager-*-Arch-x86_64.run` from
   [Releases](https://github.com/abdulrahmansh105/ash-password-manager/releases).
2. Make it executable and run it:

```bash
chmod +x ASH-Password-Manager-*-Arch-x86_64.run
./ASH-Password-Manager-*-Arch-x86_64.run
```

It asks for explicit confirmation, then -- for your user only, never
`sudo` -- creates a private virtual environment (correctly sidestepping
Arch's externally-managed system Python), installs `pykeepass`,
`argon2-cffi`, and `pycryptodomex` into it, links `ash-password-manager`
/ `ashpm` / `ash-password-manager-agent` into `~/.local/bin` (added to
your `PATH` automatically if it wasn't already there), installs the
`.desktop` entry and icon, offers to set up the optional background
agent, verifies itself with `ash-password-manager version` / `ashpm
version`, and launches `ash-password-manager sign-in`.

It still expects GTK4, Libadwaita, `python-gobject`, and `udisks2` to
already be on the system (these bind to native platform libraries and
were almost certainly already pulled in by your desktop environment;
the installer tells you the exact `pacman -S` command if anything is
missing -- it never runs `pacman`/`sudo` itself).

Run it again any time to **update or reinstall** -- it detects an
existing install and asks first, and never touches your vault, a
`.kdbx` file, `Key.key`, or any device slot. To remove everything the
installer added:

```bash
./ASH-Password-Manager-*-Arch-x86_64.run --uninstall
```

add `--purge` to also delete local settings and device Local Keys
(never your vault -- that only ever lives on your USB). See
`--help` for every flag (`--yes`, `--update`, `--no-agent`,
`--no-launch`, ...).

The source for this installer is
[`packaging/run-installer/`](packaging/run-installer/); build it
yourself with `bash packaging/run-installer/build.sh`.

<details>
<summary>Advanced / other install methods (developers, non-Arch, packagers)</summary>

### From this repository, for development

```bash
git clone https://github.com/abdulrahmansh105/ash-password-manager.git
cd ash-password-manager
python -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

### pip / pipx, on any distro

Not published to PyPI -- install straight from this repository. First
make sure the GTK stack is present via your distro's package manager
(it binds to native libraries and is not meaningfully installable via
pip): `python-gobject`/`PyGObject`, `gtk4`, `libadwaita`, `udisks2`.

```bash
pipx install "git+https://github.com/abdulrahmansh105/ash-password-manager.git" \
  --system-site-packages   # reuses the system PyGObject/GTK4 instead of trying to build them
```

### The Arch `PKGBUILD` directly

`packaging/arch/PKGBUILD` is what the `.run` installer's wheel is
built with, and is used in this project's own CI/release process --
it is not itself meant to be the end-user install path, but it works
standalone if you prefer pacman's own upgrade/uninstall tracking:

```bash
git clone https://github.com/abdulrahmansh105/ash-password-manager.git
cd ash-password-manager/packaging/arch
makepkg -si
```

Everything else (`pykeepass`, `argon2-cffi`, `pycryptodomex`) is a
normal Python dependency pulled in automatically either way. No path
here installs, requires, or depends on KeePassXC. See
[`docs/PACKAGING.md`](docs/PACKAGING.md) for more detail.

</details>

## Install from a USB (consent-based only)

An ASH vault USB never runs anything on its own just because it was
connected -- every `ASH-README.txt` points back to the normal install
commands above. `installer/bootstrap.py` is a complete, tested,
dependency-free consent-based installer (always asks for explicit
confirmation first, defaults to an unprivileged per-user install, only
then launches the app) that a user or packager can place in a vault
USB's `install/` directory; the Arch package installs a copy at
`/usr/share/ash-password-manager/installer/bootstrap.py` for exactly
that purpose. The setup wizard does not copy it onto every USB
automatically yet -- see `docs/PACKAGING.md` for the current state and
why. See spec-mandated behavior for what a bootstrap like this must
and must not do in `docs/SECURITY.md`.

## First run

```bash
ash-password-manager sign-in
```

Detects connected removable drives, walks you through creating a
vault (or adopting an existing KDBX already on the USB), registers
this device, and lets you pick your hotkey and USB-removal behavior.
Full walkthrough: [`docs/USB_SETUP.md`](docs/USB_SETUP.md).

## CLI

```bash
ash-password-manager sign-in            # Sign in (new) / Login (returning) -- the main entry point
ash-password-manager recover            # same mechanism, framed for a new/reinstalled device
ash-password-manager devices list       # list devices registered against a vault
ash-password-manager devices revoke ID  # revoke a device's Local Key
ash-password-manager backup create      # encrypted backup (never Local Keys or the master secret)
ash-password-manager backup verify --file ...
ash-password-manager backup restore --file ... --mountpoint ...
ash-password-manager agent              # run the optional USB-watch agent in the foreground
ash-password-manager doctor             # diagnostics -- never prints secrets
ash-password-manager version

# unchanged from the original single-vault design, still fully supported:
ash-password-manager show / lock / status / setup
ash-password-manager generate template --template '...' --username ash --service Discord
ash-password-manager generate random --length 32
```

`ashpm` is a short alias for `ash-password-manager`. No subcommand
ever prints a password, TOTP secret, recovery code, Local Key, or key
slot contents.

## Testing

```bash
source .venv/bin/activate
python -m pytest -q
```

549 tests: the original template engine/random generator/TOTP/
recovery-codes/config-store/USB-identity/Safety-Guard/login-strategy/
input-backend/session/Hyprland-integration/no-network-import suite
(all still green, none rewritten), plus new coverage for the key-slot
format (wrap/unwrap round-trips, tampered ciphertext/nonce/salt/AAD
each independently rejected, device-binding divergence, revocation
independence, the disaster-recovery invariant), device registry,
vault provisioning (guarded create, adoption with rollback-on-failure,
using the real pykeepass/Argon2id/AES-GCM stack throughout, not
mocks), the setup/login state machines, UDisks2 enumeration (synthetic
fixtures plus live smoke tests against this project's own development
machine), the backup format, and the shortcut-backend fallback chain.

## Demo vault

```bash
python3 demo/create_demo_vault.py --overwrite
```

Creates a throwaway, fully fake KDBX4 vault (see the script for exact
fabricated data) and re-opens it through the same code path the real
application uses. Never point this at a real vault location.

## Documentation

| Doc | Covers |
| --- | --- |
| [`docs/SECURITY.md`](docs/SECURITY.md) | What is a cryptographic guarantee vs. application policy |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | What this design does and does not defend against |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Credential architecture, key-slot format, state machines |
| [`docs/USB_SETUP.md`](docs/USB_SETUP.md) | Full first-time setup walkthrough |
| [`docs/BACKUP_RECOVERY.md`](docs/BACKUP_RECOVERY.md) | Encrypted backup/restore and disaster recovery |
| [`docs/INPUT_BACKENDS.md`](docs/INPUT_BACKENDS.md) | AT-SPI / ydotool / clipboard autotype backends |
| [`docs/PACKAGING.md`](docs/PACKAGING.md) | Install/upgrade/uninstall, building a release artifact |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Non-secret local settings |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common problems and fixes |
| [`docs/MIGRATION.md`](docs/MIGRATION.md) | Migrating from the original single-vault design |
| [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) | What to verify before cutting a release |

## Known limitations

See [`docs/SECURITY.md`](docs/SECURITY.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the complete,
honest list, including: CPython cannot guarantee secure memory erasure;
AT-SPI autotype and the GNOME/KDE shortcut backends are implemented
against their documented mechanisms but not exercised against a live
GNOME/KDE session in this project's own development environment; the
XDG GlobalShortcuts portal, while correctly implemented and verified
live, currently refuses non-sandboxed applications under
`xdg-desktop-portal-hyprland` (Hyprland's own native mechanism is used
instead, and is fully verified); and the background USB-watch agent is
a disclosed, optional exception to "nothing resident while locked",
scoped so that compromising it can only spawn the sign-in UI, never
expose a secret it never held.

## Contributing

Issues and pull requests are welcome. Before opening a PR:

```bash
source .venv/bin/activate
python -m pytest -q
```

Please keep the invariants in [`docs/SECURITY.md`](docs/SECURITY.md)
and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) intact -- in
particular, nothing in `core/` may gain a GTK dependency, and no
change may introduce a network dependency for normal operation or a
path that persists a secret outside the KDBX/key-slot format.

## License

MIT, see [`LICENSE`](LICENSE).
