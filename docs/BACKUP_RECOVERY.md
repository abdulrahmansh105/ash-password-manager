# Backup and recovery

## Create a recoverable encrypted backup

```bash
ash-password-manager backup create
ash-password-manager backup verify --file ash-backup-....ashbak
```

Use a strong, non-empty backup passphrase, and keep the backup away from
its source USB. Version 2 bundles these five files under an additional
Argon2id/AES-256-GCM encryption layer:

- `Passwords.kdbx` (still encrypted with its existing credentials)
- `Key.key`
- `vault.json`
- `devices.json` (historical roster)
- `keyslots/password.slot` (the encrypted wrapping of the vault master secret)

No device slot or device-local Local Key is included. The master secret
is never included in plaintext. Its encrypted password slot is essential:
without an existing wrapping of the same secret, a master password cannot
regenerate the random secret that opens the database.

Verification authenticates the ciphertext, checks the full required file
set and password-slot metadata, and rejects duplicate names, links,
traversal paths, and malformed members without writing to disk. It does
not open the inner KDBX: a complete recovery drill additionally requires
restoring to a scratch directory and opening it with the master password.

## Restore

```bash
ash-password-manager backup restore --file ash-backup-....ashbak \
    --mountpoint /path/to/a/mounted/usb --container-path ASH
ash-password-manager recover
```

The target directory must be absent or empty. Restore validates everything
before writing, stages files in a private sibling directory, and publishes
the restored container only on success. Existing non-empty directories
are never overwritten. Device slots are absent; register a fresh Local Key
after password login. Old roster entries are retained as history, not as
working device credentials.

**Use the master password that was active when the backup was made.**
Changing the current vault's password does not change an older backup.
After restoring an old backup, change the restored vault's master password
if appropriate and create a new backup.

## Version 1 backups from 0.2.x

Earlier backups omitted every key slot. Earlier documentation incorrectly
claimed restore could regenerate the random vault secret from a password.
Those archives cannot independently recover a managed vault. Verification
now reports this limitation instead of declaring them recoverable.

If the original vault still exists, make a new version 2 backup. Otherwise,
a surviving password slot from that same original vault can be supplied:

```bash
ash-password-manager backup restore --file old.ashbak \
    --mountpoint /path/to/a/mounted/usb --container-path ASH \
    --legacy-password-slot /safe/copy/of/password.slot
```

The slot must match the backup's vault ID and the database's original
vault master secret; use the master password associated with the supplied
slot. No slot from an unrelated or recreated vault can recover these data.
Keep any surviving original vault, key slots, and Local Keys until recovery
has been verified. The application never modifies an old archive in place.

## Limits and durability

Backups support up to 512 MiB of uncompressed archive payload; oversized
files and headers are rejected. Untrusted Argon2 headers are range-checked
before native key derivation. Failed writes remove the incomplete output.
Vault saves and JSON records use unique private temporary files, flush and
fsync before replacement. Filesystem and hardware guarantees still depend
on the USB and filesystem; safely unmount before disconnecting it.

## Lost credentials or media

| Lost | Recovery |
|---|---|
| USB, with a version 2 backup elsewhere | Restore using its backup passphrase, then log in with the master password from backup time |
| USB, without a usable backup | Vault contents cannot be recovered |
| Device Local Key | Password login, then enroll a fresh Local Key |
| Master password, with a working Local Key | Use Settings to reset the master password on that enrolled device |
| Master password, without a working Local Key | No password bypass is available |
| Backup passphrase | That archive cannot be decrypted; make a new backup from the original vault if available |

For legacy keyfile-only databases, preserve the encrypted database and its
matching key file together with appropriate protection. Managed backup
creation requires an ASH container with its password slot.
