# ASH Password Manager

A USB-first, device-bound password manager for Linux desktops. Your
vault lives on a USB drive you control; a master password protects it
everywhere, and an optional per-device **Local Key** lets a specific
computer unlock it without typing that password again -- without ever
turning the Local Key into a portable credential.

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
tests/                506 tests, fake data and synthetic fixtures only; several exercise the
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

```bash
cd packaging/arch && makepkg -si      # Arch
```
or
```bash
pipx install ash-password-manager     # anywhere with the deps above installed
```

Neither path installs, requires, or depends on KeePassXC. See
[`docs/PACKAGING.md`](docs/PACKAGING.md) for full instructions,
upgrade/uninstall steps, and the non-Arch path in more detail.

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

506 tests: the original template engine/random generator/TOTP/
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

## License

MIT, see `LICENSE`.
