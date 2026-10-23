# Changelog

## 0.4.1

- Restore the missing Auto-Type action in account details for the main multi-vault
  manager. Confirm explicitly, hide ASH, and allow five seconds to select the target
  login field before running the saved strategy with real credentials.
- Fix Test Strategy targeting its own editor: confirm fake input, hide the owning
  window, and detect the target after the same five-second handoff.
- Stop real and test input when the session locks or focus moves to another window,
  including a second window of the same application. Keep worker errors generic,
  wipe account secrets on completion, and prevent duplicate starts.
- Probe ydotool's actual local socket without sending input, respecting
  `YDOTOOL_SOCKET` and `XDG_RUNTIME_DIR`; a daemon process alone no longer counts
  as a usable backend.

## 0.4.0

- Refresh every screen with shared rounded surfaces, consistent spacing, clearer headings,
  and native theme colors, retaining ASH branding and all existing theme choices.
- Adapt the vault sidebar to narrow windows; add category counts, keyboard shortcuts,
  useful empty/search states, and prominent entry creation.
- Clarify setup steps and USB errors, prevent duplicate unlock requests, and keep
  database opening on a worker with visible progress.
- Add explicit copy actions for account details and authenticator codes, early password
  hiding, and visible clipboard feedback using the existing timed session clipboard.
- Keep generator output and actions visible while its options scroll; preserve both
  random and template modes and clear generated values when the dialog closes.
- Apply density/theme changes to open windows when Settings closes, improve editor
  controls, and test real GTK screen construction and interaction regressions.

## 0.3.1

- Reject an unwritable setup destination before requesting a master password.
- Report permission failures when staging a new vault, including root-owned
  USB filesystems, instead of leaving the wizard on “Creating your vault”.
- Deliver unexpected setup-worker errors to the UI on the main thread;
  prepare, create, and shortcut steps now dismiss their progress page on failure.
- Preserve an already created vault if a later reopen/registration step fails;
  direct the user to Sign in for recovery without deleting vault files.

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
