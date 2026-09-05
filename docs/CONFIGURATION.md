# Configuration

All local configuration lives under `~/.config/ash-password-manager/`
(respecting `XDG_CONFIG_HOME`), 0700, with 0600 files. None of it is
ever secret -- no password, key, or key slot is stored here; those
live only on the vault's own USB (`Passwords.kdbx`, `keyslots/`) and,
for a Local Key, under `~/.local/share/ash-password-manager/` on this
device only. See `docs/ARCHITECTURE.md` for the full on-disk layout.

## `settings.json`

Written and read by `config/store.py`; edited normally through
Settings, not by hand. Notable fields (see `Settings` in
`config/store.py` for the complete, current list):

| Field | Meaning |
|---|---|
| `theme` | `"ash"` (the branded white/blue look, default), `"dms"` (follow system/DMS), `"dark"`, `"light"` |
| `auto_lock_enabled`, `inactivity_timeout_seconds` | Auto-lock toggle and timeout |
| `lock_on_screen_lock`, `lock_on_suspend` | logind-triggered locking |
| `lock_on_usb_removal`, `usb_removal_action` | `"lock_immediately"` (default) or `"keep_unlocked"` |
| `usb_removal_explained` | Whether the one-time USB-removal explanation screen has been shown |
| `hotkey_accelerator`, `hotkey_backend` | The configured global shortcut and which backend applied it |
| `agent_autostart_enabled` | Whether the optional USB-watch agent should be offered/enabled at setup |
| `bootstrap_installer_enabled` | Whether a USB carries the consent-based install bootstrap (opt-in, off by default) |
| `typing_delay_ms`, `login_step_timeout_ms`, `safety_guard_mode`, ... | Autotype settings (advanced, optional feature) |

A value your version doesn't recognize, or whose type doesn't match
(e.g. a string where a number is expected), is silently reset to that
field's default rather than crashing the app -- see
`config/store.py`'s `_sanitize_types`.

## `vaults.json`

The local registry of every vault this device knows about -- identity
(UUIDs), a display name, and the on-USB container path. Never a
credential. Managed by `core/vaults/registry.py`; not meant to be
hand-edited.

## Rebrand migration

If you used this project before the "ASH Password Manager" rebrand,
your old `~/.config/password-manager/settings.json` is copied
(never moved) into the new location the first time the new config
directory is accessed, and your old `usb.json` registration becomes
the first entry in the new `vaults.json` (marked
`imported_from_legacy: true`). **The old directory is never modified
or deleted** -- if anything about the new location is ever wrong,
nothing has been destroyed. See `core/appdirs.py` and
`core/vaults/registry.py`.

## Logs

`~/.local/state/ash-password-manager/passman.log` (respecting
`XDG_STATE_HOME`). Event-ID style, enforced secret-free at the API
level (`core/security/logging.py`'s `safe_extra()` raises immediately
if a forbidden field name like `password` or `local_key` is passed to
it) -- never a place to look for a leaked credential, and never where
one should be found.

## Environment variables honored

Standard XDG only: `XDG_CONFIG_HOME`, `XDG_DATA_HOME`,
`XDG_STATE_HOME`, `XDG_RUNTIME_DIR`. Nothing application-specific is
required; a fresh environment gets sensible defaults under `~/.config`,
`~/.local/share`, `~/.local/state`, and `/run/user/<uid>`.
