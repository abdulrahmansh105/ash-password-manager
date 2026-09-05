# Security Model

This document states plainly what is a cryptographic guarantee here
and what is application policy, and does not claim more than either
actually provides. If anything below turns out to be wrong, that is a
bug in this document, not a license to assume the stronger claim.

## The one sentence that matters most

```
USB registration  = device/application policy
KDBX encryption    = the actual vault cryptographic protection
```

The application checking "is this the USB I expect" is a product
decision, not a security boundary. What actually protects the vault's
contents is the encryption on `Passwords.kdbx`, and the key material
that unlocks it. Everything below is about that key material.

## The credential architecture

```
VMS  = 32 cryptographically random bytes ("Vault Master Secret"),
       generated once per vault, never stored in the clear anywhere
KDBX = Passwords.kdbx, opened with password = base64url(VMS) + Key.key
```

`VMS` is never the thing you type. It is wrapped, LUKS-style, into
independent **key slots** on the USB:

| Slot | Key-encryption-key derivation | Unwraps when |
|---|---|---|
| `password.slot` | `Argon2id(master_password, salt, cost params in the slot)` | you type the master password |
| `device-<id>.slot` | `HKDF-SHA256(Local Key bytes ‖ optional Secret Service pepper, salt, info)` | this device's Local Key is valid |

```
KEK = HKDF-SHA256(ikm  = local_key ‖ pepper,
                  salt = slot.salt,
                  info = "ash-pm/local-key/v1" ‖ vault_id ‖ device_id ‖ binding,
                  L    = 32)
slot.ciphertext = AES-256-GCM(KEK, nonce, VMS, aad = vault_id ‖ device_id ‖ version ‖ kind)
```

Losing or deleting one slot can never affect another slot's ability to
unwrap `VMS`, because they share no key material at all -- only the
same `VMS`, which none of them store.

- **Revoking a device is real, not policy.** Revocation deletes
  `device-<id>.slot` outright. That device can no longer derive `VMS`
  even if its Local Key file is fully intact. Every other device's
  slot is untouched.
- **Changing the master password is cheap.** Only `password.slot` is
  rewrapped. `VMS` itself never changes, so no other registered device
  needs any change at all.
- **The password is never stored.** Only the output of Argon2id is
  ever used, and only as a key-encryption key, never persisted.

No custom cryptography is invented here: Argon2id (`argon2-cffi`),
HKDF-SHA256 (stdlib `hmac`/`hashlib`, a direct RFC 5869
implementation), and AES-256-GCM (`pycryptodomex`) -- composed in the
standard key-wrapping/key-slot pattern LUKS itself uses for a disk,
applied here to one small secret.

## Device binding: what actually stops a copied Local Key

A Local Key is 32 random bytes in a 0600 file named exactly
`ash-pass-manager.key`. The file alone proves nothing; what makes it
device-bound is that unwrapping a `device-<id>.slot` also requires a
**binding value** computed fresh on the device attempting the unlock,
mixed into the HKDF `info` parameter:

```
binding = SHA-256("ash-pm/binding/v1" ‖ each enabled input, in order)
  machine_id : HMAC-SHA256(key=/etc/machine-id, msg="ash-pm-device-binding-v1")
  uid        : str(os.getuid())
  username   : the current OS username
```

Copy the key file to another machine and this value differs there, so
the AES-GCM authentication tag fails to verify -- a clean, detectable
failure, never a silent wrong key. The login flow treats *any* Local
Key failure identically: fall back to the master password, exactly
once, no loop.

Each key slot records which binding inputs were used to create it
(`binding_inputs`), so re-deriving always uses the same set. A
transient read failure (e.g. `/etc/machine-id` momentarily unreadable)
therefore produces a clean password fallback, never a silently
different key that happens to also fail.

Deliberately **not** used as binding inputs: hostname alone (trivially
user-changeable, and often reused across someone's own machines) and
username alone (frequently identical across different machines).
Neither requires root, which this application must never assume it has
for normal use.

## The disaster-recovery invariant

**A Local Key can never make a vault unrecoverable.** `password.slot`
lives on the USB and depends on nothing device-local -- no
machine-id, no local file, no Secret Service. An OS reinstall, a disk
replacement, a wiped home directory, a regenerated machine-id, or a
dead keyring destroys only the *convenience* path:

```
device-local state gone / binding changed
  -> device-<id>.slot fails to unwrap (GCM authentication failure)
  -> fall back to the master password (always works, unconditionally)
  -> enrol a brand-new Local Key for the new install
```

The orphaned old slot stays listed in Settings -> Devices (marked "not
seen since ...") so it can be explicitly revoked -- it is never
silently dropped, and it never blocks the new enrollment.

This is tested directly (`tests/test_disaster_recovery.py`): the test
wipes all local device storage, changes every binding input, and
asserts the master password still unlocks the vault and a fresh device
enrolls successfully.

## The optional Secret Service pepper: tiers, stated plainly

Registering a device tries to store an extra 32-byte "pepper" in the
user's Secret Service (GNOME Keyring, KWallet, any libsecret
provider) and mix it into the device slot's key derivation:

- **`secret_service` tier** -- a pepper is stored and used. An
  attacker who copies only the key *file* off disk does not have it.
- **`file_only` tier** -- no Secret Service was reachable at
  enrollment time. The device slot is protected by the 0600 key file
  and device binding alone. Still fully functional; simply one layer
  lighter, and shown to the user as such in Settings -> Security,
  never hidden.

This project's own development machine has the libsecret
GObject-Introspection typelib available but, depending on what is
actually running, may have **no** Secret Service reachable at all (no
`gnome-keyring-daemon`; `kwalletd6` present but not always serving the
compatibility interface) -- so `file_only` is the default-exercised,
directly tested tier here, and `secret_service` activates automatically
the moment a real one is reachable. A slot created at `secret_service`
tier whose pepper later becomes unreachable (service disabled, item
deleted out-of-band) resolves to `None` and fails cleanly -- it never
substitutes a different key.

## KeePass/KDBX compatibility is a storage constraint, not a security claim

`Passwords.kdbx` is a standard KDBX4 file, written by `pykeepass`.
This project makes **no claim of cryptographic separation** from
KeePass-family tools:

- What is true: the KDBX is encrypted with AES-256 under the 256-bit
  random `VMS`, and the only wrapped copies of that key are the
  key slots described above.
- What is policy, not cryptography: ASH does not display the KDBX's
  own credentials anywhere in its UI, ships no generic import/export
  of arbitrary vaults, and treats the vault as ASH-managed end to end.
  A user or attacker who obtains `VMS` directly can open the file in
  any KeePass-compatible client -- saying otherwise would be false.
- KDBX is a **current storage format choice** (`pykeepass` is the
  storage engine used), not an architectural commitment; the key-slot
  design above does not depend on it and could sit in front of a
  different container format later without changing.
- **KeePassXC is neither installed, depended on, invoked, nor
  required anywhere in this project.** The only vault dependency is
  `pykeepass`. This is asserted directly by a test
  (`tests/test_no_keepassxc_coupling.py`), not just claimed here.

## USB identity

USB identity (LUKS UUID and/or filesystem UUID, plus vendor/model/
serial as corroborating, non-authoritative context) is what the
application uses to recognize *which* USB a vault lives on -- it is
device/application policy, restated: knowing these identifiers does
not help an attacker who does not also have the key slots and the
master password (or a valid, device-bound Local Key). They are never
treated as secret, and never used as key material themselves.

## Honest limitations

- **CPython cannot guarantee secure memory erasure.** `SecretBytes`
  wipes its backing `bytearray` in place -- a real, verifiable
  improvement over a plain `str` -- but the interpreter, the garbage
  collector, and libraries called along the way (including
  `pykeepass`'s own XML tree, which retains the KDBX password as a
  Python `str` for the life of an open vault handle) may hold
  additional copies this application cannot reach or overwrite. This
  was already true of the original design and remains true here.
- **The Local Key does not defend against an attacker already
  operating inside the same logged-in user session.** No
  "unlock without a password" feature on any platform can promise
  otherwise; this one does not try to.
- **Losing the master password loses the vault.** There is no
  recovery slot, no emergency kit, and no code-based bypass, by
  explicit design decision. `docs/BACKUP_RECOVERY.md` explains the
  one thing that does help: keeping an encrypted backup.
- **The background USB-watch agent is a disclosed, optional resident
  process** (spec section 30 requires it for auto-discovery). It holds
  no vault handle and no secret material of any kind -- see
  `packaging/systemd/README.md` for the exact blast-radius statement.
- **The XDG GlobalShortcuts portal backend, while implemented
  correctly and verified live** (its D-Bus handshake round-trips a
  real, well-formed response), **is currently refused by
  `xdg-desktop-portal-hyprland` for non-sandboxed applications**
  (`org.freedesktop.portal.Error.NotAllowed: An app id is required`),
  confirmed both as a bare process and under a proper
  `systemd-run --user --scope --unit=app-<id>.scope`. Hyprland's own
  native mechanism (`hyprctl keyword bind`) is used instead and is
  fully verified working; the portal backend remains in place for
  compositors whose implementation does not have this restriction.
- **AT-SPI autotype, and the GNOME/KDE shortcut backends, are
  implemented against their documented mechanisms but not exercised
  against a live GNOME/KDE session in this project's own development
  environment** (Hyprland is the active compositor here). This mirrors
  the project's pre-existing, honest disclosure for AT-SPI in
  `docs/INPUT_BACKENDS.md`; a KDE-specific shortcut backend was
  deliberately **not** shipped at all rather than ship one this low in
  confidence -- KDE users get the Manual fallback (Settings shows the
  exact shortcut to configure by hand) instead of a backend that might
  silently not work.
- **Universal login automation (the optional autotype feature) is
  inherently best-effort** across arbitrary third-party UIs -- the
  Safety Guard exists specifically because of this, unchanged from the
  original design.
