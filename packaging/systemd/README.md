# `ash-password-manager-agent.service` (optional, opt-in)

This *is* a deliberate change from this project's original stance
(preserved below for the history). Spec requirement (product section
30, "Auto Discovery") explicitly calls for monitoring removable-media
events so a registered vault's USB triggers the login popup on its
own, without the user first pressing the hotkey -- that is not
possible without something resident. This unit is the smallest thing
that can do it.

## What it actually does, and does not do

- Watches UDisks2 for block-device changes (`passman.integration.usb.udisks2.Udisks2Monitor`).
- When a *registered* vault's USB transitions from disconnected to
  connected, it spawns the normal `ash-password-manager sign-in`
  command -- the exact same command the hotkey runs.
- Re-applies the configured global hotkey once at startup, for
  backends (Hyprland) whose binding does not otherwise survive a
  compositor restart.
- **Holds no vault handle, no key slot, no Local Key, and no secret
  material of any kind, ever.** Compromising this process gains an
  attacker the ability to spawn the sign-in UI -- nothing it doesn't
  already have by other means -- because it never had a secret to
  leak in the first place. All of that lives only in the short-lived
  UI process it spawns, exactly as before.
- Never unlocks anything itself; it only launches the same UI that
  asks for a Local Key/password the normal way.

## Installing (opt-in, never silent)

Setup asks once (spec section 30 / "USB monitoring, hotkey, auto-lock"
build item) whether to enable this; default is **on**, but nothing
here starts anything the user didn't consent to during setup:

```bash
systemctl --user enable --now ash-password-manager-agent.service
```

Disable any time with `systemctl --user disable --now ash-password-manager-agent.service`
-- the app still works fully via the hotkey and manually running
`ash-password-manager sign-in`; only the *automatic* popup-on-insert
behavior is lost.

## Original stance (for history, no longer fully accurate)

> Deliberately not shipped. See `launcher/daemon.py`'s module
> docstring and `docs/THREAT_MODEL.md`: the host-side launcher is
> stateless and re-execed by Hyprland's own `bind = ...,exec,...` on
> every SUPER+CTRL+A press, so there is nothing for a resident
> background service to do while the vault is locked -- adding one
> would only be extra attack surface with no functional benefit.

That reasoning still holds for the **hotkey-only** path, which remains
fully stateless (`launcher/daemon.py`, `launcher/ash_daemon.py`) --
this unit exists solely for the *auto-discovery* convenience feature,
is entirely optional, and its blast radius if compromised is
documented above.
