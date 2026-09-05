# Threat model

See [`docs/SECURITY.md`](SECURITY.md) for the full credential
architecture (key slots, device binding, the disaster-recovery
invariant) -- this document is the threat table and the honestly-
disclosed trade-offs, for both the current design and the original
single-vault design it grew from (still fully supported, unchanged).

## Security boundary

**USB registration is device/application policy. KDBX encryption --
specifically, the key slots described in `docs/SECURITY.md` -- is the
actual vault cryptographic protection.** The application checking
"is this the USB I expect" never was, and is not now, what stops an
attacker with the vault's key material. This distinction is load-
bearing throughout the design and is asserted directly in code
comments at the modules that could be mistaken for a security boundary
(`core/vaults/registry.py`, `integration/usb/identity.py`).

```
USB
└── (optional) LUKS2 encrypted device       at-rest encryption, if your USB uses it
    └── filesystem
        ├── ASH/                            an ASH vault container (docs/ARCHITECTURE.md)
        │   ├── Passwords.kdbx              KDBX4, password = base64url(a random 256-bit
        │   │                               secret), never the thing you type
        │   ├── Key.key                     KeePass 2.x XML key file
        │   ├── keyslots/                   the actual credential layer -- see SECURITY.md
        │   └── devices.json, integrity.json  non-secret metadata
        └── icons/                          cached, non-secret
```

LUKS is **optional** here, unlike the original design: a plain
filesystem USB is fully supported (spec requirement: the vault must
not depend on one specific device or encryption scheme underneath).
When the selected USB *is* LUKS-encrypted, this application still
never receives the LUKS passphrase -- `udisksctl unlock` owns that
prompt directly (terminal getpass or the desktop's polkit agent), via
`integration/usb/udisks.py`, unchanged from the original design.

## What the host machine holds

| Location | Contents |
|---|---|
| `~/.config/ash-password-manager/settings.json` | Non-secret preferences (theme, auto-lock, hotkey, USB-removal policy) |
| `~/.config/ash-password-manager/vaults.json` | Vault **identity** metadata only: UUIDs, container path, display name. Never a password, key, or slot. |
| `~/.local/share/ash-password-manager/devices/<vault_id>/ash-pass-manager.key` | This device's Local Key -- device-bound (see SECURITY.md); useless if copied elsewhere |
| `~/.local/state/ash-password-manager/passman.log` | Event-ID-style status log, enforced secret-free (`core/security/logging.py`) |
| Process memory, only while a setup/login/manager window is running | The decrypted vault handle, `SecretBytes`-wrapped password/VMS during derivation, TOTP codes for their ~30s validity |
| The optional background agent's memory | Nothing secret at all, ever -- see the agent section below |

Nothing in that table, including the log file, survives past a
`lock()` call with the actual secret intact. See
`core/security/memory.py` for the honest limits of what CPython can
guarantee here.

## Threats considered

| Threat | Mitigation |
|---|---|
| Stolen laptop, USB not present | Vault inaccessible; host holds no vault secret (table above) -- only this device's now-useless-without-the-USB Local Key file |
| Stolen USB alone | The master password (Argon2id-protected) or a specific device's Local Key (device-bound, useless elsewhere) is required; see SECURITY.md |
| Copied Local Key file, wrong device | Fails the device-binding check (SECURITY.md); falls back to the password, never silently succeeds |
| Wrong/spoofed USB with a similar label | Identity check is UUID-based (LUKS and/or filesystem), never a label or mount path; `IDENTITY_MISMATCH` is distinct from `LOCKED`/`ABSENT` and always shown as "locked", never silently treated as valid |
| Revoked device attempting to unlock | Its key slot is deleted outright (real cryptographic revocation, not a flag); `DeviceRevokedError` falls back to the password path |
| Malware reading process memory while unlocked | Out of scope for a userspace Python app on a general-purpose OS -- see honest limitations; mitigated in degree by short secret lifetimes and prompt wiping |
| Autotype typing a password into the wrong window | Safety Guard (`core/auth/engine.py`, unchanged): HIGH-confidence window-class match required to auto-proceed; anything ambiguous always requires interactive confirmation |
| Password/TOTP/Local-Key/slot data leaking via logs | `core/security/logging.safe_extra()` raises immediately if a forbidden field name is logged (tested); nothing walks the vault or a key slot and logs field values |
| Password/TOTP appearing in `ps`/`/proc/<pid>/cmdline` | Every synthetic-input backend passes secrets via stdin or in-process API, never argv (tested) |
| A malicious or buggy vault entry field | Custom-property values are only ever literal text or strictly-parsed structured data -- never `eval`'d, never used to build a shell command |
| A malformed/truncated/tampered key slot or backup file | AES-GCM authentication fails closed; `SlotFormatError`/`BackupCorruptError` are distinct from a wrong credential only in message text, never in behavior -- both refuse, neither partially succeeds |
| Path traversal via a vault-relative path or a backup archive entry | `core/vaults/layout.py` resolves every path and rejects escapes; backup restoration validates archive member names before ever extracting (`core/backup/archive.py`, plus `tarfile`'s own `filter="data"`) |

## Honest limitations (documented, not hidden)

- **CPython cannot guarantee secure memory erasure.** Unchanged from
  the original design's own disclosure: `SecretBytes` wipes its
  backing `bytearray` in place, but the interpreter, GC, and libraries
  called along the way (`pykeepass`'s own XML tree included) may hold
  additional copies this application cannot reach.
- **The Local Key does not defend against an attacker already
  operating inside the same logged-in user session.** No local
  "unlock without a password" mechanism on any platform can promise
  otherwise.
- **Losing the master password loses the vault.** No recovery slot, no
  emergency kit, no code-based bypass, by explicit decision. See
  `docs/BACKUP_RECOVERY.md`.
- **AT-SPI autotype, the GNOME shortcut backend, and the XDG
  GlobalShortcuts portal backend are implemented against their
  documented mechanisms but carry real, disclosed caveats** -- see
  `docs/SECURITY.md`'s "Honest limitations" section for the exact,
  verified specifics (including the portal's confirmed rejection of
  non-sandboxed apps under `xdg-desktop-portal-hyprland`). A
  KDE-specific shortcut backend was deliberately not shipped rather
  than ship one of uncertain correctness; KDE users get the honest
  Manual fallback instead.
- **Universal login automation (the optional autotype feature) is
  inherently best-effort**, unchanged from the original design -- the
  Safety Guard exists specifically because of this.
- **Suggestion/detection uses window class and title text only** (via
  Hyprland IPC), unchanged from the original design; browser tab
  titles are treated as LOW confidence, never HIGH.

## Deliberate architecture deviation: the optional USB-watch agent

The original design's strongest claim was "while the vault is locked,
nothing at all is running for an attacker to target," achieved by
never running a resident process and re-execing the launcher fresh on
every hotkey press. **Spec section 30 (auto-discovery: a registered
vault's USB should trigger the login popup on its own, not only via
the hotkey) is not achievable without something resident**, so this
project now optionally ships `ash-password-manager-agent`
(`launcher/agent.py`, a `systemd --user` unit in `packaging/systemd/`).

This is a disclosed, scoped trade-off, not a silent regression of the
original guarantee:

- The agent **holds no vault handle, no key slot, no Local Key, and no
  secret material of any kind, ever.** Its entire job is watching
  UDisks2 for a registered vault's USB appearing, then spawning the
  exact same `ash-password-manager sign-in` command the hotkey runs.
- Compromising it gains an attacker the ability to *spawn the sign-in
  UI* -- something already reachable by the hotkey or a terminal --
  and nothing else, because it never had a secret to leak.
- It is **opt-in**, asked once during setup (default on, per spec
  section 30's requirement), and can be disabled at any time
  (`systemctl --user disable --now ash-password-manager-agent`)
  without losing any functionality except the automatic pop-up --
  the hotkey and manually running `sign-in` still work exactly the
  same.
- The **hotkey-only path remains exactly as stateless as the original
  design**: `launcher/daemon.py` (legacy) and `launcher/ash_daemon.py`
  (new) are both still re-execed fresh by the compositor on every
  press, with nothing resident required for that path alone.

See `packaging/systemd/README.md` for the complete before/after
reasoning.
