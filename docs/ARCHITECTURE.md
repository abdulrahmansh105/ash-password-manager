# Architecture

See [`docs/SECURITY.md`](SECURITY.md) for the cryptographic design in
full detail. This document maps modules and on-disk layout.

## Layering

```
core/          toolkit-independent; no GTK imports anywhere in here
config/        non-secret local settings (this machine only)
integration/   Linux desktop glue: UDisks2, shortcuts, Hyprland, logind
input/         synthetic-input backends for the optional autotype feature
ui/            GTK4 + Libadwaita
launcher/      process entry points + local IPC (single-instance check)
cli/           argparse CLI
```

`core/` never imports `ui/`, `integration/`, or `launcher/`. Every
credential/vault/flow module in `core/` is independently unit-tested
without a display, matching the project's original design principle.

## Credential architecture

```
core/crypto/
  kdf.py       Argon2id (master password) + HKDF-SHA256 (Local Key)
  aead.py      AES-256-GCM sealing, fixed nonce/tag sizes, one error type
  binding.py   device-binding value (machine-id HMAC + uid + username)
  keyslots.py  the key-slot format: create/unwrap password & device slots,
               password rewrap (VMS unchanged), VMS<->KDBX-password encoding

core/devices/
  local_key.py    the on-device ash-pass-manager.key file + its identity.json
  secret_store.py optional libsecret pepper, with an explicit
                  secret_service/file_only tier, never silently substituted
  registry.py     the on-USB devices.json + key-slot file I/O; the actual
                  product operations: register_device, unlock_with_local_key,
                  unlock_with_password, revoke_device, change_master_password

core/vaults/
  layout.py    traversal-safe paths for one vault container on a USB
  health.py    a tamper-evident (SHA-256) integrity manifest + health checks
  registry.py  the LOCAL list of every vault this device knows about
               (~/.config/ash-password-manager/vaults.json) -- distinct from
               core.devices.registry, which is the devices *inside* one vault

core/vault/
  kdbx.py         KDBX4 compatibility layer (pre-existing, unmodified except
                  one additive VaultHandle.rekey() method for adoption)
  provisioning.py create_new_vault() / adopt_existing_vault(): guarded,
                  transactional (temp-directory-then-rename, or
                  backup-then-rollback), the only two ways a vault gets made
```

## On-USB layout

A "container" is the directory holding one vault's `Passwords.kdbx`;
a single USB can hold several independent containers (multiple
vaults). New vaults use `ASH/`; an adopted vault keeps its existing
directory.

```
<mount>/
  ASH-README.txt          plain text: what this USB is, normal install commands
  install/                optional, opt-in at setup -- consent-based bootstrap only
  ASH/
    vault.json             {schema_version, vault_id, name, created_utc, app}
    Passwords.kdbx          KDBX4 / AES-256 / Argon2id (pykeepass's own KDF,
                            separate from and additional to the key-slot layer)
    Key.key                 KeePass 2.x XML keyfile, 256-bit random, 0600
    keyslots/
      password.slot          the master-password-wrapped VMS
      device-<device_id>.slot one per registered device
    devices.json             [{device_id, label, tier, registered_utc,
                              last_seen_utc, revoked_utc, os_release}]
    integrity.json           SHA-256 of vault.json/devices.json/each slot
    icons/                   non-secret, pre-existing feature
    backups/                 optional, for locally-kept encrypted backups
```

## Local, per-device (never on the USB)

```
~/.local/share/ash-password-manager/devices/<vault_id>/
  ash-pass-manager.key   0600, 32 random bytes -- the exact required filename
  device.json            0600 -- {device_id, vault_id, label, created_utc, tier}
~/.config/ash-password-manager/
  settings.json          app settings (theme, auto-lock, hotkey, USB-removal policy, ...)
  vaults.json            the local vault registry (identity + display metadata only)
```

## State machines

```
core/flows/setup_machine.py   FIRST_RUN -> USB_SELECTION -> [ADOPT_OR_CREATE]
                               -> PASSWORD_CREATION -> LOCAL_KEY_OPTIONAL
                               -> VAULT_CREATION -> DEVICE_REGISTRATION
                               -> HOTKEY_SETUP -> USB_REMOVAL_CONFIGURATION
                               -> SETUP_COMPLETE

core/flows/login_machine.py   USB_DETECTED -> IDENTIFY_USB -> CHECK_LOCAL_KEY
                               -- valid --> UNLOCK_WITH_LOCAL_KEY --+
                               -- else  --> ASK_PASSWORD -----------+--> MANAGER
```

Both are pure Python (no GTK, no I/O beyond what is injected as
callables) and fully unit-tested, including the exact "never ask for
the password if the Local Key succeeds, never loop back to the Local
Key once fallen back to the password" guarantees.

`core/flows/usb_setup.py` and `core/flows/usb_login_lookup.py` do the
actual UDisks2/`udisksctl` orchestration (unlock/mount) the two state
machines above are driven with; both keep their pure decision logic
(which block on a drive is the right one to use, whether a registered
vault's USB is currently connected) separate from that I/O so it is
unit-testable with synthetic fixtures.

## UI

```
ui/setup/     the first-time setup wizard (Adw.NavigationView, one page per state)
ui/login/     the login popup (Adw.ApplicationWindow + a small Gtk.Stack of states)
ui/manager/   the main, post-unlock window (Adw.NavigationSplitView: categories +
              search + entry list), opened after either flow succeeds
ui/theme.py   the white/blue ASH brand palette, as a second GTK.CssProvider layered
              on top of (and, when selected, above) DMS's live theme injection --
              "Follow system" remains one Settings toggle away and behaves exactly
              as the original zero-hardcoded-color design did
```

`ui/app.py`'s `PasswordManagerApp` is extended, not rewritten: an
`unlocked_vault` constructor kwarg lets the new setup/login flows hand
over an already-authenticated `VaultHandle`, skipping the legacy
keyfile-only `open_vault(..., password=None)` path entirely, while
every other subsystem (control server, logind watcher, inactivity/
USB-removal ticking, lock/teardown) is reused unchanged for both
flows. Which primary window it opens (the original autotype-focused
`AccountPickerWindow`, or the new `ManagerWindow`) is decided by
whether `unlocked_vault` was supplied.

The pre-existing dialogs (`EntryEditorDialog`, `AccountDetailDialog`,
`GeneratorDialog`, `SettingsDialog`, the TOTP/recovery-code dialogs)
are reused as-is by the new Manager -- none of them needed to know
which front door opened the vault.

## Autotype (optional, secondary)

`core/auth/`, `input/`, and the strategy editor are unchanged from the
original design: login-automation into third-party applications,
gated by the Safety Guard's window-identity confidence check. Reachable
only from an entry's detail view and Settings -> Authentication, never
part of the Sign in/Login/Manager flow.

## Distribution

The public source tree and built package contain no personal vault,
key, or key slot -- see `.gitignore` and
[`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md). Normal
installation is the distributable package (Arch `PKGBUILD` or `pipx`),
documented in [`docs/PACKAGING.md`](PACKAGING.md). `installer/
bootstrap.py` is a complete, tested, dependency-free, strictly
consent-based launcher for that same package (never a second install
mechanism, and never something that runs on its own just because a USB
was connected) -- placing a copy of it onto a specific vault USB's
`install/` directory is currently a manual step for a user or packager
(the Arch package installs a copy at `/usr/share/ash-password-manager/
installer/bootstrap.py`); the setup wizard does not automate that copy
step yet, since doing so for a `pip`/`pipx`-based install would need a
wheel-bundling mechanism not built here (see `docs/PACKAGING.md`).
