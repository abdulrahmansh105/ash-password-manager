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
anything to check). Real end-to-end behavior against your actual target
apps (Discord, GitHub, Google, Steam, ...) needs your live Hyprland
session -- untested in this development environment, which has no
display (see `docs/THREAT_MODEL.md`).
