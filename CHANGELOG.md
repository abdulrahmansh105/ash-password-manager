# Changelog

## 0.3.0

- Repair encrypted backup recovery: version 2 retains the wrapped password
  slot; version 1 recovery explicitly requires a surviving original slot.
- Validate complete archives before restore, reject malformed members and
  excessive KDF resource requests, and stage restore before publication.
- Save vaults through private fsynced temporary files; serialize ASH writers
  and reject stale database handles instead of silently losing newer edits.
- Refuse direct vault creation over existing files, clear credentials on
  failed opens, and use unpredictable setup and JSON temporary files.
- Preserve custom Auto-Type targets while editing; add website URL and
  target editing, with visible save errors and safe retry behavior.
- Require confirmation for partial/regex application matches, stop Auto-Type
  after session lock or detected target changes, and release secrets on
  early exits and backend failures.
- Use elapsed time for inactivity locking and finish lock teardown even if
  clipboard cleanup fails. Clear only clipboard content owned by the app;
  mark copied secrets as sensitive for cooperating clipboard managers.
- Validate stored TOTP configurations, handle the epoch verification window,
  and apply ambiguous-character exclusion to custom symbols consistently.
- Copy an adopted vault's external USB key to its managed location; preserve
  the original key and reject paths outside the selected USB.
- Detect missing device slots in health manifests and report malformed
  manifests without crashing. Probe accessibility-bus availability before
  entering libatspi, which can otherwise abort when no bus is accessible.
- Repair AT-SPI text entry and delegate navigation keys to ydotool when
  available. Generator and Auto-Type clipboard copies now share the session
  owner so locking clears them and configured timeouts are respected.
- Add regression coverage, automated CI, and wheel-content checks. Installer
  builds use explicit installed tooling and do not upgrade the user's Python
  environment or resolve dependencies over the network.

Existing encrypted vaults retain their storage format, credentials, and
entries. No database migration is required. Old backup passwords follow the
backup's snapshot; changing the current password does not update an archive.
