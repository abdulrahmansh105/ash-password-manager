#!/usr/bin/env bash
# ASH Password Manager -- self-extracting installer.
#
# This is a plain shell script with a gzipped tar archive appended
# after the __ASH_PAYLOAD_BELOW__ marker (built by build.sh). It
# extracts that archive to a temp directory and hands off to
# install.sh -- see that file for what actually gets installed and
# where. No source checkout, git, pipx, or manual dependency install
# is needed; this file is the entire download.
#
# Source: https://github.com/abdulrahmansh105/ash-password-manager
set -euo pipefail

MARKER="__ASH_PAYLOAD_BELOW__"
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"

ARCHIVE_LINE=$(awk -v m="$MARKER" '$0==m {print NR + 1; exit}' "$SELF")
if [ -z "${ARCHIVE_LINE:-}" ]; then
    echo "error: corrupt installer (payload marker not found)" >&2
    exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ash-password-manager-install.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

tail -n "+$ARCHIVE_LINE" "$SELF" | tar xz -C "$WORKDIR"
chmod +x "$WORKDIR/install.sh"

"$WORKDIR/install.sh" --payload-dir "$WORKDIR" "$@"
status=$?
exit "$status"
__ASH_PAYLOAD_BELOW__
