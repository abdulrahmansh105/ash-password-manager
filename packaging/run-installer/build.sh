#!/usr/bin/env bash
# Builds ASH-Password-Manager-Installer.run (and a version-suffixed
# copy for GitHub Releases) from this source tree.
#
# This script itself is a maintainer/CI tool, not something an end
# user ever runs -- end users only ever download and run the single
# .run file it produces. It never bundles a vault, .kdbx, Key.key,
# device slot, or any personal data; it fails loudly if it ever finds
# any of that in the payload it's about to ship.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/packaging/run-installer"
DIST="$ROOT/dist"
BUILD_PYTHON="${ASH_PM_PYTHON:-python3}"

VERSION=$("$BUILD_PYTHON" -c "
import tomllib
with open('$ROOT/pyproject.toml', 'rb') as f:
    print(tomllib.load(f)['project']['version'])
")

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
PAYLOAD="$WORKDIR/payload"
mkdir -p "$PAYLOAD" "$DIST"

echo "==> Building wheel for version $VERSION"
# Use explicit installed build tools; building must not upgrade the user's
# environment or fetch dependencies implicitly.
"$BUILD_PYTHON" -m build --wheel --no-isolation --outdir "$WORKDIR/dist" "$ROOT" >/dev/null
"$BUILD_PYTHON" "$ROOT/scripts/check_wheel.py" "$WORKDIR"/dist/ash_password_manager-*-py3-none-any.whl

cp "$WORKDIR"/dist/ash_password_manager-*-py3-none-any.whl "$PAYLOAD/"
cp "$ROOT/password-manager.desktop" "$PAYLOAD/dev.ash.PasswordManager.desktop"
cp "$ROOT/assets/icons/password-manager.svg" "$PAYLOAD/password-manager.svg"
cp "$ROOT/packaging/systemd/ash-password-manager-agent.service" "$PAYLOAD/"
cp "$ROOT/LICENSE" "$PAYLOAD/LICENSE"
cp "$HERE/install.sh" "$PAYLOAD/install.sh"
chmod +x "$PAYLOAD/install.sh"

echo "==> Scanning payload for anything that must never be shipped"
if find "$PAYLOAD" \( \
        -iname '*.kdbx*' -o -iname 'Key.key' -o -iname 'ash-pass-manager.key' \
        -o -iname '*.slot' -o -iname '*.ashbak' -o -iname 'vault.json' \
        -o -iname 'devices.json' -o -iname 'integrity.json' -o -iname 'usb.json' \
        -o -iname 'settings.json' -o -ipath '*/ASH/*' -o -ipath '*/metadata/*' \
    \) | grep -q .; then
    echo "REFUSING TO BUILD: forbidden personal/vault file found in installer payload:" >&2
    find "$PAYLOAD" \( -iname '*.kdbx*' -o -iname 'Key.key' -o -iname '*.slot' \) >&2
    exit 1
fi

echo "==> Packing payload"
tar -C "$PAYLOAD" -czf "$WORKDIR/payload.tar.gz" .

OUT="$DIST/ASH-Password-Manager-Installer.run"
cat "$HERE/stub.sh" "$WORKDIR/payload.tar.gz" > "$OUT"
chmod +x "$OUT"

ARCH="$(uname -m)"
VERSIONED="$DIST/ASH-Password-Manager-${VERSION}-Arch-${ARCH}.run"
cp "$OUT" "$VERSIONED"

echo "==> Built:"
echo "    $OUT"
echo "    $VERSIONED"
echo "    ($(du -h "$OUT" | cut -f1))"
