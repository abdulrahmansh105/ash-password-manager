"""Consent-based USB install bootstrap (spec section 18).

Not part of the ``passman`` package and never imported by it -- this
lives here so it can be copied, standalone, onto a vault USB's
``install/`` directory (an explicit, opt-in choice made during setup;
see ``core/vault/provisioning.py``'s ``ASH-README.txt`` and
``docs/PACKAGING.md``). Kept dependency-free (stdlib only) because it
runs on a machine that does not have this project's own dependencies
installed yet.
"""
