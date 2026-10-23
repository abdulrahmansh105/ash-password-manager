# Input backends: what each one actually supports

`input/backend.py` defines `AuthInputBackend`; the login engine
(`core/auth/engine.py`) never talks to a specific mechanism directly.
Backend **selection** (`input/__init__.py`'s `select_backend()`) always
prefers the most structurally-precise option available and only falls
further down the list when the preferred one genuinely isn't usable --
blind global keystroke injection is never the *only* mechanism, it's the
fallback.

## Selection order

```
1. AT-SPI (AtspiBackend)         -- structural, sets field content directly
2. ydotool (YdotoolBackend)      -- global synthetic input, works everywhere
3. Clipboard paste (opt-in only) -- only if "Allow clipboard fallback" is on
```

## Backend compatibility matrix

| Backend | Mechanism | Works with | Does NOT work with | Setup required |
|---|---|---|---|---|
| **AT-SPI** | Reads the accessibility tree, finds the focused editable object, sets its text content directly (`Atspi.EditableText.set_text_contents`) | GTK3/GTK4 apps, Qt apps with accessibility enabled, Electron apps built with `--force-renderer-accessibility` or that have accessibility turned on (many browsers auto-enable it once any AT-SPI client connects), most native Wayland toolkit apps | Apps with accessibility explicitly disabled; some Electron/Chromium apps that never enable their accessibility tree; games and custom-rendered UIs (canvas/GL logins) | `at-spi2-core` running (usually already active as part of a normal desktop session); no udev/group changes needed |
| **ydotool** | Global synthetic keyboard input via `ydotoold` + `/dev/uinput`, works at the Wayland compositor level (not X11-specific) | Everything with keyboard focus -- browsers, Electron, native Wayland apps, **XWayland apps** (XWayland apps receive input the same way as any other window under Hyprland; ydotool doesn't need to know which one it is) | Nothing structurally -- but it's "blind": it types into whatever currently has keyboard focus, which is exactly why the Safety Guard exists | `ydotoold` running (systemd --user service) + your user in the `input` group + a udev rule granting `/dev/uinput` access. **Not root.** See `packaging/arch/PKGBUILD`'s `optdepends`. |
| **Clipboard paste** | `wl-copy` then a synthetic Ctrl+V via the ydotool backend | Any app that accepts a normal paste | Anything that blocks paste into password fields (rare, but some do) | `wl-clipboard`; **off by default**, requires "Allow clipboard fallback" in Settings |

## Why AT-SPI is preferred when available

It doesn't touch global keyboard focus at all -- it writes directly into
the specific accessible object it found, which is both more reliable
(no dropped keystrokes from typing too fast for a slow-rendering app)
and safer (there's no window in which a stray keypress or a focus change
mid-type sends characters somewhere else).

## Why ydotool is still necessary

Not every application exposes a usable accessibility tree (spec section
12 explicitly calls out not assuming one universal mechanism works). For
those, global synthetic input is the only remaining local, no-cloud,
no-browser-extension option on Wayland/Hyprland.

## What is explicitly NOT implemented

- **X11-only mechanisms** (`XTestFakeKeyEvent`, `xdotool`) -- this is a
  Wayland-first project per your environment; XWayland apps are already
  covered by ydotool without needing an X11-specific path.
- **Browser-extension-based autofill** -- explicitly excluded by your
  requirements.
- **A universal "read the focused field's role/name to auto-target
  it" AT-SPI query** -- `AtspiBackend.focus_field()` intentionally
  returns `UNAVAILABLE` rather than guessing; the executor falls back to
  Tab-navigation (from the account's `AuthStrategy`) instead, since a
  generic "find the field that looks like a password field" heuristic
  across arbitrary apps is exactly the kind of fragile guess this
  project avoids making silently.

## Verifying on your machine

```bash
ash-password-manager doctor
```

reports which backend is currently available (never requires typing
anything to check). The ydotool check connects to the same local datagram
socket as its client, without sending events: `YDOTOOL_SOCKET` takes precedence,
then `$XDG_RUNTIME_DIR/.ydotool_socket`, then `/tmp/.ydotool_socket` when no
runtime directory is set. A missing, stale, or inaccessible socket reports
unavailable even if a daemon process exists.

In the manager, open an account, then **Authentication Flow → Auto-Type**.
Confirm the real-credential action, switch to the intended application during
the five-second delay, and click its first login field. The saved strategy runs
only after that handoff. A completed sequence reports input delivery, not proof
that the website accepted the login.

To check navigation first, open **Edit Auto-Type Strategy → Test Strategy**.
Confirm the fake-credential test and select the target field during the same
delay. The test never reads the account's real credentials. A login strategy
can submit the fake form, so use a disposable target when possible.

Both actions require readable target-window information and stop if the session
locks or the detected target changes. On Hyprland, the compositor window address
distinguishes two windows of the same application. Titles may change during a
multi-page login without stopping the run. This does not verify browser URL/tab
identity or recall input already sent by a backend.

The automated tests cover target handoff, fake versus real-account execution
using fabricated credentials, cancellation, duplicate starts, backend failures,
and secret cleanup. Real end-to-end behavior against your actual target apps
(Discord, GitHub, Google, Steam, ...) still requires a live Hyprland session.
The October 24 check could not access the desktop/input sockets from its restricted
execution environment; live keystroke delivery was not verified.
