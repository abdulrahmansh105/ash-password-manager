#!/usr/bin/env bash
# ASH Password Manager -- local, per-user installer.
#
# Runs from inside the self-extracted payload of
# ASH-Password-Manager-Installer.run (see packaging/run-installer/stub.sh
# and build.sh). Can also be run directly for development, from a
# directory containing the built wheel and the other payload files
# (pass --payload-dir explicitly, or run it from that directory).
#
# Hard rules this script enforces:
#   * Never uses sudo/pkexec. Everything happens under $HOME.
#   * Never installs, touches, or looks at a vault, .kdbx, Key.key,
#     device slot, or any of this user's ASH settings -- it only
#     manages its OWN venv, symlinks, desktop entry, icon, and the
#     optional systemd --user unit.
#   * Detects an existing install and asks Update/Reinstall/Cancel
#     instead of silently overwriting anything.
#   * Requires explicit consent before doing anything, unless --yes.
set -euo pipefail

APP_ID="ash-password-manager"
APP_DISPLAY_NAME="ASH Password Manager"
SOURCE_URL="https://github.com/abdulrahmansh105/ash-password-manager"

XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"

APP_DATA_HOME="$XDG_DATA_HOME/$APP_ID"
VENV_DIR="$APP_DATA_HOME/venv"
MANIFEST="$APP_DATA_HOME/.installer-manifest"

BIN_DIR="$HOME/.local/bin"
APPLICATIONS_DIR="$XDG_DATA_HOME/applications"
ICON_DIR="$XDG_DATA_HOME/icons/hicolor/scalable/apps"
SYSTEMD_USER_DIR="$XDG_CONFIG_HOME/systemd/user"

DESKTOP_FILE_NAME="dev.ash.PasswordManager.desktop"
ICON_FILE_NAME="password-manager.svg"
SERVICE_FILE_NAME="ash-password-manager-agent.service"
COMMANDS=(ash-password-manager ashpm ash-password-manager-agent)

PAYLOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSUME_YES=0
DO_UNINSTALL=0
PURGE=0
FORCE_UPDATE=0
NO_LAUNCH=0
AGENT_CHOICE=""   # "", "yes", "no"

log()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have_tty() { ( : < /dev/tty ) 2>/dev/null; }

usage() {
    cat <<EOF
ASH Password Manager installer

Usage: $(basename "$0") [options]

  -y, --yes            Assume "yes" to all prompts (non-interactive)
      --update         Non-interactively update an existing install
      --reinstall      Non-interactively wipe and reinstall
      --uninstall      Remove ASH Password Manager (app only; see --purge)
      --purge          With --uninstall, also remove local settings and
                        device keys (never touches your vault -- that
                        lives on your USB and this installer never
                        goes near it)
      --agent          Enable the optional background USB-watch agent
      --no-agent       Skip the optional background agent entirely
      --no-launch      Do not launch the app after installing
      --payload-dir D  Read the wheel/desktop/icon/service from D
  -h, --help           Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes) ASSUME_YES=1 ;;
        --update) FORCE_UPDATE=1 ;;
        --reinstall) FORCE_UPDATE=1 ;;
        --uninstall) DO_UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        --agent) AGENT_CHOICE="yes" ;;
        --no-agent) AGENT_CHOICE="no" ;;
        --no-launch) NO_LAUNCH=1 ;;
        --payload-dir) PAYLOAD_DIR="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done

confirm() {
    local prompt="$1"
    if [ "$ASSUME_YES" = 1 ]; then
        return 0
    fi
    if ! have_tty; then
        warn "no terminal available to ask for confirmation; assuming no (pass --yes to run non-interactively)"
        return 1
    fi
    local answer
    read -r -p "$prompt [y/N]: " answer </dev/tty || answer="n"
    case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

do_uninstall() {
    if [ ! -f "$MANIFEST" ] && [ ! -d "$VENV_DIR" ]; then
        log "$APP_DISPLAY_NAME does not appear to be installed here (nothing found at $APP_DATA_HOME)."
        exit 0
    fi

    log "This will remove:"
    log "  - $VENV_DIR"
    log "  - $BIN_DIR/{${COMMANDS[*]}}"
    log "  - $APPLICATIONS_DIR/$DESKTOP_FILE_NAME"
    log "  - $ICON_DIR/$ICON_FILE_NAME"
    log "  - $SYSTEMD_USER_DIR/$SERVICE_FILE_NAME (disabled first, if enabled)"
    if [ "$PURGE" = 1 ]; then
        log "  - $APP_DATA_HOME (ALL local app data, including device Local Keys)"
        log "  - $XDG_CONFIG_HOME/$APP_ID (local settings)"
        log ""
        log "Your vault (Passwords.kdbx and its key slots) lives on your USB drive"
        log "and is never touched by this installer, with or without --purge."
    fi
    confirm "Proceed with uninstall?" || { log "Cancelled."; exit 0; }

    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user disable --now "$SERVICE_FILE_NAME" >/dev/null 2>&1 || true
    fi
    rm -f "$SYSTEMD_USER_DIR/$SERVICE_FILE_NAME"

    for cmd in "${COMMANDS[@]}"; do
        target="$BIN_DIR/$cmd"
        if [ -L "$target" ]; then
            case "$(readlink -f "$target" 2>/dev/null || true)" in
                "$VENV_DIR"/*) rm -f "$target" ;;
            esac
        fi
    done

    rm -f "$APPLICATIONS_DIR/$DESKTOP_FILE_NAME"
    rm -f "$ICON_DIR/$ICON_FILE_NAME"
    rm -rf "$VENV_DIR"
    rm -f "$MANIFEST"

    if [ "$PURGE" = 1 ]; then
        rm -rf "$APP_DATA_HOME"
        rm -rf "$XDG_CONFIG_HOME/$APP_ID"
    fi

    update_desktop_caches
    log "[OK] $APP_DISPLAY_NAME uninstalled."
    exit 0
}

# ---------------------------------------------------------------------------
# System dependency check (never auto-installs these -- they need pacman,
# i.e. root; this installer never calls sudo)
# ---------------------------------------------------------------------------

check_system_deps() {
    local missing=()

    if ! python3 -c "
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw
" >/dev/null 2>&1; then
        missing+=("python-gobject" "gtk4" "libadwaita")
    fi

    if ! command -v udisksctl >/dev/null 2>&1 && ! command -v lsblk >/dev/null 2>&1; then
        missing+=("udisks2" "util-linux")
    fi

    if [ "${#missing[@]}" -gt 0 ]; then
        local unique
        unique=$(printf '%s\n' "${missing[@]}" | sort -u | tr '\n' ' ')
        warn "Missing system packages needed to RUN $APP_DISPLAY_NAME: $unique"
        if command -v pacman >/dev/null 2>&1; then
            log "Install them with:"
            log "  sudo pacman -S --needed $unique"
        else
            log "Install the equivalent packages for your distribution."
        fi
        log "This installer never runs pacman/sudo itself."
        confirm "Continue installing anyway?" || { log "Cancelled. Nothing was changed."; exit 0; }
    fi
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

find_wheel() {
    local wheel
    wheel=$(find "$PAYLOAD_DIR" -maxdepth 1 -name 'ash_password_manager-*.whl' | sort | tail -n 1)
    [ -n "$wheel" ] || die "no ash_password_manager-*.whl found in $PAYLOAD_DIR (corrupt installer?)"
    printf '%s' "$wheel"
}

update_desktop_caches() {
    command -v update-desktop-database >/dev/null 2>&1 && \
        update-desktop-database "$APPLICATIONS_DIR" >/dev/null 2>&1 || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 && \
        gtk-update-icon-cache -q "$XDG_DATA_HOME/icons/hicolor" >/dev/null 2>&1 || true
}

ensure_path_has_local_bin() {
    case ":$PATH:" in
        *":$BIN_DIR:"*) return 0 ;;
    esac
    export PATH="$BIN_DIR:$PATH"

    local marker="# Added by ASH Password Manager installer ($SOURCE_URL)"
    local line='export PATH="$HOME/.local/bin:$PATH"'
    local rc="$HOME/.profile"
    if [ -f "$rc" ] && grep -qF "$marker" "$rc" 2>/dev/null; then
        return 0
    fi
    {
        printf '\n%s\n%s\n' "$marker" "$line"
    } >> "$rc"
    log "Added $BIN_DIR to PATH via $rc (open a new shell, or run: source $rc)"
}

do_install() {
    local existing_version=""
    if [ -f "$MANIFEST" ]; then
        existing_version=$(grep -m1 '^version=' "$MANIFEST" 2>/dev/null | cut -d= -f2 || true)
    fi

    if [ -d "$VENV_DIR" ] || [ -n "$existing_version" ]; then
        log "$APP_DISPLAY_NAME is already installed${existing_version:+ (version $existing_version)}."
        if [ "$FORCE_UPDATE" = 0 ] && [ "$ASSUME_YES" = 0 ]; then
            log "  [1] Update / reinstall (recommended -- keeps your local settings and device keys)"
            log "  [2] Cancel"
            local choice="2"
            if have_tty; then
                choice="1"
                read -r -p "Choose [1]: " choice </dev/tty || choice="1"
            else
                warn "no terminal available to ask; assuming Cancel (pass --yes or --update to run non-interactively)"
            fi
            [ "$choice" = "2" ] && { log "Cancelled. Nothing was changed."; exit 0; }
        fi
        log "Replacing the existing installation (your settings, device keys, and vault are not touched)."
    fi

    log "$APP_DISPLAY_NAME installer"
    log "Source: $SOURCE_URL"
    log ""
    log "This will install, for your user only (no root/sudo):"
    log "  - A private Python environment at $VENV_DIR"
    log "  - Commands in $BIN_DIR: ${COMMANDS[*]}"
    log "  - A desktop entry and icon"
    log "  - Optionally, a user systemd unit for the background USB-watch agent"
    log ""
    log "It will NOT create a vault, and will NOT read, modify, or migrate"
    log "any existing vault, .kdbx file, Key.key, or device slot."
    confirm "Proceed with installation?" || { log "Cancelled. Nothing was installed."; exit 0; }

    check_system_deps

    local wheel
    wheel=$(find_wheel)
    log "Using $(basename "$wheel")"

    log "Creating virtual environment..."
    rm -rf "$VENV_DIR"
    mkdir -p "$APP_DATA_HOME"
    python3 -m venv --system-site-packages "$VENV_DIR"

    log "Installing $APP_DISPLAY_NAME and its Python dependencies..."
    "$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
    "$VENV_DIR/bin/python" -m pip install --quiet "$wheel"

    mkdir -p "$BIN_DIR"
    for cmd in "${COMMANDS[@]}"; do
        if [ -x "$VENV_DIR/bin/$cmd" ]; then
            ln -sf "$VENV_DIR/bin/$cmd" "$BIN_DIR/$cmd"
        else
            warn "expected command $cmd was not installed by the wheel"
        fi
    done

    mkdir -p "$APPLICATIONS_DIR" "$ICON_DIR"
    install -m 644 "$PAYLOAD_DIR/$DESKTOP_FILE_NAME" "$APPLICATIONS_DIR/$DESKTOP_FILE_NAME"
    install -m 644 "$PAYLOAD_DIR/$ICON_FILE_NAME" "$ICON_DIR/$ICON_FILE_NAME"
    update_desktop_caches

    setup_agent

    ensure_path_has_local_bin

    local version
    version=$(basename "$wheel" | sed -E 's/^ash_password_manager-([0-9][^-]*)-.*/\1/')
    {
        printf 'version=%s\n' "$version"
        printf 'installed_at=%s\n' "$(date -Iseconds 2>/dev/null || date)"
        printf 'venv=%s\n' "$VENV_DIR"
    } > "$MANIFEST"

    verify_install
    launch_app
}

setup_agent() {
    local choice="$AGENT_CHOICE"
    if [ -z "$choice" ]; then
        if [ "$ASSUME_YES" = 1 ]; then
            choice="no"
        elif confirm "Enable the optional background USB-watch agent now? (can be turned off any time)"; then
            choice="yes"
        else
            choice="no"
        fi
    fi

    mkdir -p "$SYSTEMD_USER_DIR"
    install -m 644 "$PAYLOAD_DIR/$SERVICE_FILE_NAME" "$SYSTEMD_USER_DIR/$SERVICE_FILE_NAME"

    if [ "$choice" = "yes" ]; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --user daemon-reload >/dev/null 2>&1 || true
            if systemctl --user enable --now "$SERVICE_FILE_NAME" >/dev/null 2>&1; then
                log "Background agent enabled (systemctl --user status $SERVICE_FILE_NAME)."
            else
                warn "could not enable the background agent (no user systemd session here); unit installed but inactive."
            fi
        else
            warn "systemctl not found; agent unit installed but not enabled."
        fi
    fi
}

verify_install() {
    log "Verifying installation..."
    if ! "$BIN_DIR/ash-password-manager" version; then
        die "ash-password-manager version failed -- installation did not complete correctly."
    fi
    if ! "$BIN_DIR/ashpm" version; then
        die "ashpm version failed -- installation did not complete correctly."
    fi
    log "[OK] $APP_DISPLAY_NAME installed."
}

launch_app() {
    if [ "$NO_LAUNCH" = 1 ]; then
        log "Skipping launch (--no-launch). Run: ash-password-manager sign-in"
        return 0
    fi
    log "Launching $APP_DISPLAY_NAME..."
    if ! ( "$BIN_DIR/ash-password-manager" sign-in >/dev/null 2>&1 & disown ) ; then
        warn "could not launch automatically. Run: ash-password-manager sign-in"
    fi
}

if [ "$DO_UNINSTALL" = 1 ]; then
    do_uninstall
else
    do_install
fi
