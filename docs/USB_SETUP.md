# USB setup

## The normal path: the setup wizard

```bash
ash-password-manager sign-in
```

With no vault registered yet, this opens the first-time setup wizard.
It walks through, in order:

1. **Select your password USB** -- every removable drive UDisks2 can
   see, labeled by vendor/model/size (e.g. "Kingston DataTraveler
   2.0 (15.5 GB)"), never a raw `/dev/sdX` path. If the drive is
   LUKS-encrypted, unlocking it happens through `udisksctl unlock` --
   your desktop's normal passphrase prompt (polkit agent or terminal),
   never this application. A plain (non-LUKS) filesystem USB works
   too; LUKS is optional here, not required.
2. **(If a non-ASH KDBX is already on the selected USB)** -- adopt it
   (keeping every entry, re-keyed into the ASH key-slot model) or
   create a fresh vault alongside it instead. This is scoped to the
   USB you just selected; there is no generic "browse for a file"
   import anywhere in this application.
3. **Create Password** -- your master password, with a strength
   indicator. Minimum 8 characters. Wrapped into `password.slot` via
   Argon2id; never stored in plaintext.
4. **Create Local Key?** -- optional. Generating one lets *this
   specific device* unlock the vault later without retyping the
   password. Skipping is always fine; the master password keeps
   working everywhere regardless.
5. The vault is created (or the adoption is completed) and this device
   is registered, right here -- see `docs/ARCHITECTURE.md`'s state
   machine for exactly why this step happens now, before the two
   settings-only steps that follow.
6. **Choose your hotkey** -- press the combination you want; it's
   applied immediately via whichever backend actually works on this
   system (`integration/shortcuts/`, tried in order: the XDG portal,
   Hyprland's native mechanism, GNOME's `gsettings`, then a manual
   instructions fallback). Change it later in Settings -> Shortcuts.
7. **USB Removal Protection** -- an explanation screen, then the
   choice (default: lock immediately). Change it later in Settings ->
   Security.

The vault is then open: the Manager appears.

## Re-registering / adding another vault

Run `ash-password-manager sign-in` again with a different (or newly
reformatted) USB connected and no window already open -- it detects
that this USB isn't a registered vault and offers setup again. Each
vault gets its own entry in `~/.config/ash-password-manager/vaults.json`;
see `docs/ARCHITECTURE.md` for multi-vault support.

## New device, existing vault

Connect an already-registered vault's USB on a device that has never
seen it before:

```
USB detected -> no Local Key for this device -> enter the master password
  -> successful login -> "Set up passwordless login on this device?"
  -> Skip, or Generate Key (a brand-new one, never copied from anywhere)
```

## Recovery

```bash
ash-password-manager recover
```

Exactly the same mechanism as "new device" above, exposed as its own
named entry point for a reinstalled OS or a replacement machine: select
the vault's USB, enter the master password, register this device with
a fresh Local Key. There is no separate recovery code and no bypass --
see `docs/SECURITY.md`'s disaster-recovery invariant for why the
master password is guaranteed to still work even after a full
reinstall.

## Legacy path (still supported, unchanged)

The original single-vault, keyfile-only flow still works exactly as
it always did:

```bash
ash-password-manager setup   # register a USB by LUKS/filesystem UUID directly
ash-password-manager show    # open it -- the original AccountPickerWindow, no password ever
```

This is a genuinely different vault model (no master password, no
key slots, no device registration) -- it is not migrated automatically
into the new model; use the setup wizard's adoption step (above) if
you want to move such a vault over.

## Doctor

```bash
ash-password-manager doctor
```

Runs the original diagnostic checks (Wayland/Hyprland session, GTK4
theme file, `pykeepass`, input backend, `wl-clipboard`) plus the
legacy USB-identity chain, unchanged. Never prints a secret.
