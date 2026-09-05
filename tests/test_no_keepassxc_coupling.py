"""Spec-mandated boundary check: ASH must not install, depend on, or
invoke KeePassXC anywhere (see docs/SECURITY.md's "KeePass
compatibility is a storage constraint" section). The vault format
(KDBX4, via ``pykeepass``) staying KeePass-*compatible* is a
deliberate, honestly-documented storage choice -- these tests assert
there is no actual coupling to the separate KeePassXC *application*
(no subprocess/binary invocation, no packaging dependency), not that
the word "KeePassXC" never appears in an explanatory comment (several
legitimately do, e.g. kdbx.py's module docstring on field-format
compatibility)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = PROJECT_ROOT / "src"

# Deliberately narrow: an actual binary/module coupling, not any
# mention of the word "KeePassXC" (which also appears, correctly, in
# comments about KDBX field-format compatibility).
_KEEPASSXC_INVOCATION_RE = re.compile(r"keepassxc-cli|keepassxc\.exe|keepassxc_cli", re.IGNORECASE)


def _source_files():
    yield from SRC_ROOT.rglob("*.py")


def test_no_source_file_invokes_a_keepassxc_binary():
    offenders = [
        str(path.relative_to(SRC_ROOT))
        for path in _source_files()
        if _KEEPASSXC_INVOCATION_RE.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"Found a KeePassXC binary reference in: {offenders}"


def test_no_source_file_imports_a_keepassxc_package():
    offenders = [
        str(path.relative_to(SRC_ROOT))
        for path in _source_files()
        if re.search(r"^\s*(import|from)\s+keepassxc\b", path.read_text(encoding="utf-8"), re.MULTILINE)
    ]
    assert offenders == [], f"Found a KeePassXC import in: {offenders}"


def test_pyproject_dependencies_do_not_include_keepassxc():
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data.get("project", {})
    all_deps = list(project.get("dependencies", []))
    for extra_deps in project.get("optional-dependencies", {}).values():
        all_deps.extend(extra_deps)
    assert not any("keepassxc" in dep.lower() for dep in all_deps)
    assert any("pykeepass" in dep.lower() for dep in all_deps)


def test_pkgbuild_depends_array_does_not_include_keepassxc():
    pkgbuild_path = PROJECT_ROOT / "packaging" / "arch" / "PKGBUILD"
    if not pkgbuild_path.exists():
        return
    text = pkgbuild_path.read_text(encoding="utf-8")
    match = re.search(r"^depends=\(([^)]*)\)", text, re.MULTILINE)
    assert match is not None, "PKGBUILD has no depends=() array to check"
    assert "keepassxc" not in match.group(1).lower()
