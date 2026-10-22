# ASH interface refresh — 0.4.0

The refresh retains ASH's wordmark, rounded forms, blue emphasis, GTK/Libadwaita
controls and existing ASH light, dark, light and system/DMS theme choices. It
changes presentation and interaction without changing the vault format.

## Shared design

- Native named colors keep system palettes and contrast preferences intact.
- Shared spacing, form widths, headings, icon surfaces, focus rings and error
  treatments apply to setup, login, locked state, manager and dialogs.
- Forms scroll within a constrained width on both small and large windows.
- Existing no-transition behavior is applied consistently across entry points.

## Screen coverage

| Surface | Improvements |
| --- | --- |
| Setup | Named steps, visible progress, USB icon/list, prominent permission errors, disabled Continue without a drive, password guidance and Enter submission |
| Login | Vault identity, clearer unlock action, busy feedback, duplicate submission guard, worker error recovery and asynchronous database opening |
| Locked | Consistent brand styling and clear USB instruction |
| Manager | Adaptive category sidebar, counts, prominent Add entry, search/results counts, distinct empty/category/search states, Ctrl+F/N/L and Enter to open first result |
| Quick sign-in | Separate heading/search, contextual instruction, keyboard hints and consistent row styling |
| Account details | Clear identity and field rows, URL/notes display, explicit timed clipboard copy, TOTP copy, early password hiding and recovery confirmation retry |
| Entry editor | Grouped introduction, consistent field spacing, persistent Save/Cancel actions and visible validation feedback |
| Generator | Random default plus preserved template mode, pinned output/actions, copy feedback and input cleanup on close |
| Authenticator/recovery | Shared dialog sizing, clearer instructions and readable input areas |
| Auto-type editor | Numbered steps, readable sequence preview and disabled invalid movement controls |
| Settings | Search, readable appearance labels, save behavior explanation, live theme/density application on close; all existing pages retained |

## Verification

`tests/test_ui_experience.py` constructs the real GTK screens against synthetic
account metadata and isolated XDG paths. It also covers search/category states,
setup progress, duplicate login protection, worker-based database opening,
clipboard ownership/timeouts, early re-hide, generator cleanup and live density.

Visual checks use an isolated GTK Broadway display and synthetic data, including
980px desktop and 390px narrow manager layouts. Check setup with/without a USB,
permission errors, password/progress pages, login, locked state, entry/details,
generator, authenticator, recovery, auto-type and settings. The generator actions
remain reachable while options scroll. No real vault is needed for these checks.

Before release, run the full test suite, build the wheel and run
`scripts/check_wheel.py`. Installation uses the existing application-only backup
and checks that personal settings/device data metadata remains unchanged.
