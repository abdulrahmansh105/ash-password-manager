# Backup and recovery

## What a backup contains, exactly

```bash
ash-password-manager backup create
```

Prompts for a backup passphrase, then writes one `ash-backup-<vault>-
<timestamp>.ashbak` file containing exactly four things, packed and
then encrypted as one unit (Argon2id-derived key, AES-256-GCM):

- `Passwords.kdbx`
- `Key.key`
- `vault.json`
- `devices.json`

## What is never in a backup

- **No key slot** (`password.slot` or any `device-*.slot`). The
  password slot is trivially regenerated on restore from whatever
  master password you supply then -- so a backup made before a
  password change still restores correctly with your *current*
  password, never a stale one. Device slots are device-bound and
  meaningless once restored onto different hardware anyway.
- **No Local Key, ever, from any device.** It never leaves the device
  it was generated on, backup or not.
- **The Vault Master Secret, in any form.** Not stored anywhere, not
  even inside the encrypted archive.
- **Plaintext entries.** The KDBX inside the archive is exactly as
  encrypted as it is on the USB; the archive's own encryption is an
  additional, independent layer around the whole bundle.

## Restoring

```bash
ash-password-manager backup restore --file ash-backup-....ashbak \
    --mountpoint /path/to/a/mounted/usb --container-path ASH
```

Restoring **always** requires the master password afterward and
**always** registers the restoring device as new -- a backup is not a
way to transplant a specific device's identity, only the vault's
contents and its device roster's history. The target directory must
be empty; restoration refuses to overwrite existing files.

```bash
ash-password-manager backup verify --file ash-backup-....ashbak
```

Decrypts and validates the archive's structure without writing
anything to disk -- confirms the passphrase is correct and the bundle
is well-formed.

## What losing things means

| Lost | Consequence |
|---|---|
| The USB, with a `.ashbak` backup elsewhere | Restore the backup onto a new USB, then run `ash-password-manager recover` |
| The USB, no backup | Vault contents unrecoverable |
| A device's Local Key file | That device falls back to the master password automatically; revoke the orphaned slot in Settings -> Devices whenever convenient |
| The master password, USB intact | **Vault unrecoverable.** There is no recovery slot and no code-based bypass, by explicit design decision (see `docs/SECURITY.md`) |
| A backup passphrase | That specific backup file is unrecoverable; the vault itself is unaffected -- make a new backup |

## Legacy vaults (keyfile-only, no master password)

The original single-vault design has no master password to lose in
the first place -- `Key.key` *is* the credential. Back up
`Passwords.kdbx` and `Key.key` together, with equivalent protection
(not, for instance, a plaintext cloud sync of just the key file); if
`Key.key` is lost with no backup, that vault is unrecoverable. This
project's `backup create`/`restore` commands operate on ASH-format
vaults (with key slots); a legacy vault's two files can simply be
copied directly with normal filesystem tools.
