# Migrating from password-template-generator

`password-template-generator` is untouched by this project -- it remains
installable and usable standalone. This document is for if/when you want
to fold its use into `password-manager` instead.

## What ported directly, unchanged

`passman.core.generator.template_engine` is a line-for-line port of
`ptgen.core.engine`: same grammar (`{USERNAME}`, `{USERNAME || FALLBACK}`,
`{SERVICE_NAME}`), same errors, same behavior. Any template string you
were using with `password-template` produces the exact same output
through `password-manager generate template`:

```bash
# old
password-template --template '#Tpl{USERNAME || ASH}123{SERVICE_NAME}911' \
  --username ash --service Discord

# new -- identical output
password-manager generate template --template '#Tpl{USERNAME || ASH}123{SERVICE_NAME}911' \
  --username ash --service Discord
```

and from inside the app: the account picker's generator icon opens the
same Template tab, and "Generate Password" in the entry editor can use
either mode.

## What did NOT carry over as-is

- **Saved templates/services** (`~/.config/password-template-generator/
  templates.json` / `services.json`) are not auto-imported. They were
  designed for a tool with no vault to attach them to; in
  `password-manager`, a template's real home is inside each account
  entry (or you can keep typing the raw template string into the
  generator each time, same as before). If you want your saved template
  *list* available as quick-picks in the new generator UI, that's a
  small, well-scoped follow-up (read `templates.json`, populate a
  dropdown) -- not implemented in this first pass since it's genuinely
  optional (the underlying engine is what mattered, and that's ported
  exactly).
- **Generated passwords were never persisted by either tool** -- there's
  nothing password-shaped to migrate.

## Recommended migration steps

1. Keep using `password-template-generator` for anything you're not
   ready to move into a vault entry yet -- it's unaffected.
2. For accounts you want fully managed (autotype, TOTP, recovery codes):
   create the entry in `password-manager` (`+` in the account picker),
   and if you used a template-derived password for that account, either
   regenerate it with the same template (Template tab) and paste it in
   as the entry's password, or use `+Generate Password` inline in the
   entry editor if you're fine with a new value.
3. Uninstall `password-template-generator` only when/if you're
   comfortable that its saved templates/services aren't something you
   still need standalone -- they live entirely under
   `~/.config/password-template-generator/` and are untouched by
   `password-manager`'s own config directory
   (`~/.config/password-manager/`).

## Coexistence

Both apps can be installed simultaneously with no conflicts -- different
package names, different binaries (`password-template` vs
`password-manager`), different config directories, different D-Bus
application IDs (`dev.ash.PasswordTemplateGenerator` vs
`dev.ash.PasswordManager`).
