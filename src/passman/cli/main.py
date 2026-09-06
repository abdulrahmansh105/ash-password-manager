"""Command-line interface.

Never prints secrets by default (spec section 36) -- no subcommand here
reads a password, TOTP secret, or recovery code from the vault and
prints it; the only thing that ever touches vault secrets is the GUI's
explicit reveal/autotype actions.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import __version__
from ..config.store import (
    UsbRegistration,
    load_settings,
    load_usb_registration,
    save_usb_registration,
)
from ..core.generator import (
    PolicyError,
    RandomPasswordPolicy,
    TemplateError,
    generate,
    generate_random_password,
)
from ..input import select_backend
from ..integration.hyprland import keybind as hypr
from ..integration.usb.identity import UsbState, check_vault_paths, evaluate_usb_status
from ..integration.usb.udisks import UdisksError, list_block_devices
from ..launcher.daemon import run_show
from ..launcher.ipc import send_command


def _cmd_sign_in(_args: argparse.Namespace) -> int:
    """New multi-vault flow (spec sections 1, 26, 27): Sign in for a
    first-time user (no vaults registered yet), Login for a returning
    one -- ``launcher.ash_daemon`` decides which, based on
    ``core.vaults.registry``. Distinct from the legacy single-vault
    `show`/`unlock` above, which remain unchanged for anyone still
    using a keyfile-only vault registered the original way."""
    from ..launcher.ash_daemon import run_sign_in_or_login

    return run_sign_in_or_login()


def _cmd_devices_list(args: argparse.Namespace) -> int:
    from ..core.devices.registry import list_devices
    from ..core.flows.usb_login_lookup import find_and_mount_vault
    from ..core.vaults.layout import VaultLayout

    record = _resolve_vault(args.vault_id)
    if record is None:
        return 1
    mountpoint = find_and_mount_vault(record)
    if mountpoint is None:
        print(f"error: the USB for vault {record.name!r} is not connected.", file=sys.stderr)
        return 1
    layout = VaultLayout.at(mountpoint, record.container_rel_path)
    for device in list_devices(layout):
        status = "revoked" if device.is_revoked else "active"
        print(f"{device.device_id}  {device.label!r}  tier={device.tier}  status={status}  last_seen={device.last_seen_utc}")
    return 0


def _cmd_devices_revoke(args: argparse.Namespace) -> int:
    from ..core.devices.registry import revoke_device
    from ..core.flows.usb_login_lookup import find_and_mount_vault
    from ..core.vaults.layout import VaultLayout

    record = _resolve_vault(args.vault_id)
    if record is None:
        return 1
    mountpoint = find_and_mount_vault(record)
    if mountpoint is None:
        print(f"error: the USB for vault {record.name!r} is not connected.", file=sys.stderr)
        return 1
    layout = VaultLayout.at(mountpoint, record.container_rel_path)
    revoke_device(layout, args.device_id)
    print(f"[OK] Device {args.device_id} revoked. Its Local Key can no longer unlock this vault.")
    return 0


def _resolve_vault(vault_id: str | None):
    from ..core.vaults.registry import load_vaults

    vaults = load_vaults()
    if not vaults:
        print("error: no vaults registered. Run `ash-password-manager sign-in` first.", file=sys.stderr)
        return None
    if vault_id:
        match = next((v for v in vaults if v.vault_id == vault_id), None)
        if match is None:
            print(f"error: no vault with id {vault_id!r}.", file=sys.stderr)
        return match
    if len(vaults) > 1:
        print("error: multiple vaults registered; pass --vault-id. Known vaults:", file=sys.stderr)
        for v in vaults:
            print(f"  {v.vault_id}  {v.name!r}", file=sys.stderr)
        return None
    return vaults[0]


def _cmd_backup_create(args: argparse.Namespace) -> int:
    import getpass

    from ..core.backup.archive import BackupError, backup_filename, create_backup
    from ..core.flows.usb_login_lookup import find_and_mount_vault
    from ..core.security.memory import SecretBytes
    from ..core.vaults.layout import VaultLayout

    record = _resolve_vault(args.vault_id)
    if record is None:
        return 1
    mountpoint = find_and_mount_vault(record)
    if mountpoint is None:
        print(f"error: the USB for vault {record.name!r} is not connected.", file=sys.stderr)
        return 1
    layout = VaultLayout.at(mountpoint, record.container_rel_path)
    output = args.output or backup_filename(record.name)
    passphrase = SecretBytes(getpass.getpass("Backup passphrase: "))
    try:
        create_backup(layout, Path(output), passphrase)
    except BackupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"[OK] Backup written to {output}")
    return 0


def _cmd_backup_verify(args: argparse.Namespace) -> int:
    import getpass

    from ..core.backup.archive import BackupError, verify_backup
    from ..core.security.memory import SecretBytes

    passphrase = SecretBytes(getpass.getpass("Backup passphrase: "))
    try:
        verify_backup(Path(args.file), passphrase)
    except BackupError as exc:
        print(f"error: backup is invalid: {exc}", file=sys.stderr)
        return 1
    print("[OK] Backup is valid and the passphrase is correct.")
    return 0


def _cmd_backup_restore(args: argparse.Namespace) -> int:
    import getpass

    from ..core.backup.archive import BackupError, restore_backup
    from ..core.security.memory import SecretBytes
    from ..core.vaults.layout import VaultLayout

    layout = VaultLayout.at(args.mountpoint, args.container_path)
    passphrase = SecretBytes(getpass.getpass("Backup passphrase: "))
    try:
        restore_backup(Path(args.file), layout, passphrase)
    except BackupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"[OK] Restored to {layout.container_dir}")
    print("This device is not yet registered for the restored vault -- run `ash-password-manager sign-in`")
    print("with its USB connected and log in with the master password to register it.")
    return 0


def _cmd_agent(_args: argparse.Namespace) -> int:
    from ..launcher.agent import run_agent

    return run_agent()


def _cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def _cmd_show(_args: argparse.Namespace) -> int:
    return run_show()


def _cmd_lock(_args: argparse.Namespace) -> int:
    response = send_command("lock")
    if response == "ok":
        print("[OK] vault session locked")
        return 0
    print("[OK] no active session (already locked)")
    return 0


def _cmd_status(_args: argparse.Namespace) -> int:
    reg = load_usb_registration()
    if reg is None:
        print("USB: not registered (run `password-manager setup`)")
        return 0

    try:
        devices = list_block_devices()
        status = evaluate_usb_status(devices, reg)
        print(f"USB identity: {status.state.value}")
        if status.mountpoint:
            print(f"Vault mountpoint: {status.mountpoint}")
    except UdisksError as exc:
        print(f"USB detection error: {exc}")

    session_status = send_command("status")
    print(f"Session: {session_status or 'not running (locked)'}")
    return 0


def _doctor_line(ok: bool, label: str) -> None:
    print(f"[{'OK' if ok else 'WARN'}] {label}")


def _cmd_doctor(_args: argparse.Namespace) -> int:
    import os
    import shutil
    from pathlib import Path

    _doctor_line(bool(os.environ.get("WAYLAND_DISPLAY")), "Wayland session detected")
    _doctor_line(bool(os.environ.get("HYPRLAND_INSTANCE_SIGNATURE")), "Hyprland detected")
    _doctor_line(hypr.is_available(), "hyprctl available")
    gtk_css = Path.home() / ".config" / "gtk-4.0" / "gtk.css"
    _doctor_line(gtk_css.exists(), "GTK4 theme file present (DMS/Matugen integration)")

    # This block reports five distinct identity facts, in the order the
    # security chain actually depends on them -- each is only checked
    # once the one before it holds, and none of them ever reads a file's
    # *contents* (existence checks only; see check_vault_paths()).
    reg = load_usb_registration()
    _doctor_line(reg is not None, "USB identity")

    if reg is not None:
        try:
            devices = list_block_devices()
            status = evaluate_usb_status(devices, reg)
            _doctor_line(status.state != UsbState.ABSENT, "LUKS identity")
            _doctor_line(
                status.state in (UsbState.MOUNTED, UsbState.UNLOCKED_NOT_MOUNTED),
                "filesystem identity",
            )
            if status.state == UsbState.MOUNTED and status.mountpoint:
                paths = check_vault_paths(status.mountpoint, reg)
                _doctor_line(paths.vault_exists, f"vault relative path ({reg.vault_rel_path})")
                _doctor_line(paths.keyfile_exists, f"key file relative path ({reg.keyfile_rel_path})")
        except UdisksError:
            _doctor_line(False, "USB/LUKS detection (udisksctl/lsblk unavailable)")

    _doctor_line(True, "TOTP backend available (stdlib hmac/hashlib)")

    settings = load_settings()
    backend = select_backend(allow_clipboard_fallback=settings.clipboard_fallback_enabled)
    _doctor_line(backend is not None, f"Input backend available ({backend.name if backend else 'none'})")

    try:
        import pykeepass  # noqa: F401

        _doctor_line(True, "pykeepass available")
    except ImportError:
        _doctor_line(False, "pykeepass NOT installed (pacman -S python-pykeepass)")

    _doctor_line(shutil.which("wl-clipboard") is not None or shutil.which("wl-copy") is not None, "wl-clipboard available")
    return 0


def _cmd_setup(args: argparse.Namespace) -> int:
    print("password-manager setup")
    print("This will register the USB that holds your KDBX vault by its")
    print("stable LUKS/filesystem identity (never a mount path or label).\n")

    try:
        devices = list_block_devices()
    except UdisksError as exc:
        print(f"error: cannot list block devices: {exc}", file=sys.stderr)
        return 1

    candidates = []
    for root in devices:
        for dev in root.walk():
            if dev.fstype == "crypto_LUKS":
                candidates.append(dev)

    if not candidates:
        print("No LUKS2 encrypted devices currently detected. Plug in the")
        print("USB (it can stay locked) and re-run this command.")
        return 1

    print("Detected LUKS devices:")
    for i, dev in enumerate(candidates):
        print(f"  [{i}] {dev.path}  UUID={dev.uuid}")

    if args.non_interactive:
        choice = 0
    else:
        raw = input(f"Select device [0-{len(candidates) - 1}]: ").strip()
        choice = int(raw) if raw else 0

    outer = candidates[choice]
    fs_uuid = args.filesystem_uuid
    if not fs_uuid and not args.non_interactive:
        fs_uuid = input(
            "Filesystem UUID of the *unlocked* inner ext4 volume (unlock it once via "
            "your file manager/udisksctl and check `lsblk -f`), or leave blank to skip "
            "for now and re-run setup after first unlock: "
        ).strip()

    reg = UsbRegistration(
        luks_uuid=outer.uuid or "",
        filesystem_uuid=fs_uuid or "",
        vault_rel_path=args.vault_path,
        keyfile_rel_path=args.keyfile_path,
        label=args.label or "",
    )
    save_usb_registration(reg)
    print(f"\n[OK] USB registered (LUKS UUID {reg.luks_uuid[:8]}...).")

    if not fs_uuid:
        print("[!] Filesystem UUID not set yet -- unlock the USB once and re-run")
        print("    `password-manager setup --filesystem-uuid <uuid>` to finish registration.")

    if hypr.register_runtime_bind("password-manager show"):
        print("[OK] SUPER+CTRL+A registered for this Hyprland session.")
    else:
        print("[WARN] Could not register the shortcut via hyprctl (is Hyprland running?).")

    include_path = hypr.write_persistent_include("password-manager show")
    print(f"[OK] Wrote {include_path}")
    print("Add this line to your ~/.config/hypr/hyprland.conf (once) so the shortcut")
    print("survives a Hyprland restart:\n")
    print(f"    {hypr.source_line_for(include_path)}\n")
    return 0


def _cmd_generate_template(args: argparse.Namespace) -> int:
    try:
        result = generate(args.template, username=args.username, service_name=args.service)
    except TemplateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(result)
    return 0


def _cmd_generate_random(args: argparse.Namespace) -> int:
    policy = RandomPasswordPolicy(
        length=args.length,
        use_lower=not args.no_lower,
        use_upper=not args.no_upper,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
        exclude_ambiguous=args.exclude_ambiguous,
    )
    try:
        print(generate_random_password(policy))
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ash-password-manager")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version").set_defaults(func=_cmd_version)

    sub.add_parser(
        "sign-in", help="Sign in (first run) or Login (returning) -- the new multi-vault flow."
    ).set_defaults(func=_cmd_sign_in)
    sub.add_parser("login", help="Alias for `sign-in`.").set_defaults(func=_cmd_sign_in)
    sub.add_parser(
        "recover", help="Recover access on a new/reinstalled device: password login + register this device."
    ).set_defaults(func=_cmd_sign_in)

    devices = sub.add_parser("devices", help="Manage devices registered against an ASH vault.")
    devices_sub = devices.add_subparsers(dest="devices_command")
    devices_list_p = devices_sub.add_parser("list", help="List registered devices for a vault.")
    devices_list_p.add_argument("--vault-id", default=None)
    devices_list_p.set_defaults(func=_cmd_devices_list)
    devices_revoke_p = devices_sub.add_parser("revoke", help="Revoke a device's Local Key for a vault.")
    devices_revoke_p.add_argument("device_id")
    devices_revoke_p.add_argument("--vault-id", default=None)
    devices_revoke_p.set_defaults(func=_cmd_devices_revoke)

    backup = sub.add_parser("backup", help="Encrypted vault backup/restore (never Local Keys or the master secret).")
    backup_sub = backup.add_subparsers(dest="backup_command")
    backup_create_p = backup_sub.add_parser("create", help="Create an encrypted backup of a vault.")
    backup_create_p.add_argument("--vault-id", default=None)
    backup_create_p.add_argument("--output", default=None)
    backup_create_p.set_defaults(func=_cmd_backup_create)
    backup_verify_p = backup_sub.add_parser("verify", help="Verify a backup file opens with a passphrase.")
    backup_verify_p.add_argument("--file", required=True)
    backup_verify_p.set_defaults(func=_cmd_backup_verify)
    backup_restore_p = backup_sub.add_parser("restore", help="Restore a backup onto an already-mounted USB path.")
    backup_restore_p.add_argument("--file", required=True)
    backup_restore_p.add_argument("--mountpoint", required=True)
    backup_restore_p.add_argument("--container-path", default="ASH")
    backup_restore_p.set_defaults(func=_cmd_backup_restore)

    sub.add_parser(
        "agent", help="Run the background USB-watch agent in the foreground (normally a systemd --user service)."
    ).set_defaults(func=_cmd_agent)

    sub.add_parser("show", help="Open the account picker (what SUPER+CTRL+A runs, legacy single-vault flow).").set_defaults(func=_cmd_show)
    sub.add_parser("unlock", help="Alias for `show` -- unlocking happens through the picker flow.").set_defaults(func=_cmd_show)
    sub.add_parser("lock", help="Lock the active vault session, if any.").set_defaults(func=_cmd_lock)
    sub.add_parser("status", help="Print non-sensitive USB/vault/session status.").set_defaults(func=_cmd_status)
    sub.add_parser("doctor", help="Diagnose USB/vault/input/desktop integration. Never prints secrets.").set_defaults(func=_cmd_doctor)

    setup_p = sub.add_parser("setup", help="Legacy: register a keyfile-only vault USB directly (no wizard).")
    setup_p.add_argument("--vault-path", default="Passwords.kdbx")
    setup_p.add_argument("--keyfile-path", default="Key.key")
    setup_p.add_argument("--filesystem-uuid", default="")
    setup_p.add_argument("--label", default="")
    setup_p.add_argument("--non-interactive", action="store_true")
    setup_p.set_defaults(func=_cmd_setup)

    gen = sub.add_parser("generate", help="Password generation (template or random). No vault access.")
    gen_sub = gen.add_subparsers(dest="generate_command")

    tpl = gen_sub.add_parser("template", help="Deterministic template mode (ported from password-template-generator).")
    tpl.add_argument("--template", required=True)
    tpl.add_argument("--username", default="")
    tpl.add_argument("--service", default="")
    tpl.set_defaults(func=_cmd_generate_template)

    rnd = gen_sub.add_parser("random", help="CSPRNG random mode.")
    rnd.add_argument("--length", type=int, default=24)
    rnd.add_argument("--no-lower", action="store_true")
    rnd.add_argument("--no-upper", action="store_true")
    rnd.add_argument("--no-digits", action="store_true")
    rnd.add_argument("--no-symbols", action="store_true")
    rnd.add_argument("--exclude-ambiguous", action="store_true")
    rnd.set_defaults(func=_cmd_generate_random)

    return parser


def dispatch() -> int:
    argv = sys.argv[1:]
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


def main() -> None:
    sys.exit(dispatch())


if __name__ == "__main__":
    main()
