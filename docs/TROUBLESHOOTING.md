# Troubleshooting

Run `ash-password-manager doctor` first for a quick, secret-free
diagnostic pass. The sections below cover what it won't catch.

## "USB detected, but I'm asked for my password every time" (Local Key not working)

- Confirm a Local Key was actually generated: Settings -> Devices ->
  "This Device" should show "Local Key: Enabled". If it says "Not
  enabled," generate one there, or re-run `ash-password-manager
  recover` and choose Generate Key when offered.
- If it says Enabled but you're still prompted, the device-binding
  check is failing -- most commonly because `/etc/machine-id` changed
  (a fresh OS install, a container/VM that regenerates it, or a
  cloned disk image). This is by design (see `docs/SECURITY.md`'s
  disaster-recovery invariant) -- your master password always still
  works; log in with it once to enroll a fresh Local Key for the
  current machine identity.
- Check whether this device was revoked: Settings -> Devices -> Other
  Devices. A revoked device always falls back to the password, by
  design.

## "This USB doesn't match a registered vault"

- The vault must have been set up (or adopted) through
  `ash-password-manager sign-in` on some device first. A USB with a
  KeePass/KeePassXC-created (or pre-ASH) KDBX on it is not
  automatically recognized -- run `sign-in`, select that USB, and use
  the adoption offer.
- Confirm you're using the *same* USB stick -- identity is by
  filesystem/LUKS UUID, never a label, so a differently-formatted or
  cloned drive will not match even with the same volume label.

## The global shortcut doesn't do anything

Settings -> Shortcuts shows which backend actually applied it
(`hotkey_backend`). In order of preference:

1. **`portal`** (XDG GlobalShortcuts) -- confirmed, on this project's
   own development machine, to be **refused** by
   `xdg-desktop-portal-hyprland` for a normally-installed (non-Flatpak)
   application (`NotAllowed: An app id is required`). If Settings
   shows `portal` as the applied backend but the shortcut doesn't
   fire, this is very likely why; re-recording the shortcut will fall
   through to Hyprland's own mechanism instead. See `docs/SECURITY.md`.
2. **`hyprland`** -- verified working via `hyprctl keyword bind`.
   Runtime-only: if you restart Hyprland, either re-run
   `ash-password-manager sign-in` once, or enable the optional agent
   (`ash-password-manager-agent`), which re-applies it automatically
   at login.
3. **`gnome`** -- via `gsettings`; requires the
   `org.gnome.settings-daemon.plugins.media-keys` schema to actually
   be installed (it usually isn't on a non-GNOME setup, in which case
   this backend correctly reports itself unavailable rather than
   silently failing).
4. **`manual`** -- Settings shows the exact accelerator to bind by
   hand in your desktop's own keyboard-shortcut settings (needed on
   KDE Plasma and Sway today -- see `docs/SECURITY.md` for why no
   automatic backend is shipped for those yet).

## The USB isn't detected at all

- `ash-password-manager doctor` reports whether UDisks2 is reachable.
- Confirm the drive shows up in `udisksctl status` or your file
  manager at all -- this application enumerates via the same UDisks2
  service everything else on the desktop uses.
- A LUKS-encrypted USB must actually be unlockable by your desktop's
  normal mechanism (polkit agent); this application never bypasses
  that prompt.

## "Vault could not be opened" after a correct password/Local Key

This means the *key material* was correct (VMS was recovered) but the
KDBX file itself is corrupted or unreadable. Check Settings -> Vault
-> "Check Vault Health" for specifics. If `Passwords.kdbx` or
`Key.key` is genuinely damaged, restore from a backup
(`docs/BACKUP_RECOVERY.md`) -- there is no way to open a KDBX whose
own contents are corrupted, independent of having the right key.

## Autotype isn't working for a specific app

See `docs/INPUT_BACKENDS.md` for the compatibility matrix -- this is
an optional, best-effort feature, and `doctor` reports which input
backend is active.

## Filing an issue

Include the output of `ash-password-manager doctor` and, if relevant,
the last few lines of `~/.local/state/ash-password-manager/passman.log`
(it is enforced secret-free, but review it yourself before sharing
regardless).
