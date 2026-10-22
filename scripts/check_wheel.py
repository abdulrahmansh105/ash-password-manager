"""Fail packaging if a wheel includes vault or credential material."""

from __future__ import annotations

import sys
from pathlib import Path
from zipfile import ZipFile

CREDENTIAL_NAMES = {
    "Key.key",
    "ash-pass-manager.key",
    "vault.json",
    "devices.json",
    "integrity.json",
    "usb.json",
    "settings.json",
}
CREDENTIAL_SUFFIXES = (".kdbx", ".slot", ".ashbak", ".pre-ash-backup")


def check(path: Path) -> None:
    with ZipFile(path) as wheel:
        names = wheel.namelist()
    unsafe = [
        name
        for name in names
        if Path(name).name.casefold() in {value.casefold() for value in CREDENTIAL_NAMES}
        or any(part in name.casefold() for part in (".kdbx", ".pre-ash-backup"))
        or name.casefold().endswith(CREDENTIAL_SUFFIXES)
        or name.casefold().startswith(("demo/", "tests/"))
    ]
    if unsafe:
        raise SystemExit(
            f"Credential or development files in wheel: {', '.join(unsafe)}"
        )
    if "passman/ui/style.css" not in names:
        raise SystemExit("Wheel is missing the desktop stylesheet.")
    print(
        f"Verified {path.name}: {len(names)} members, stylesheet present, no credential files."
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_wheel.py path/to/package.whl")
    check(Path(sys.argv[1]))
