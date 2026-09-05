"""Minimal local control-socket IPC between the CLI and the running UI
process.

Only one UI process runs at a time (the picker/main window). It listens
on a Unix domain socket under ``$XDG_RUNTIME_DIR`` (mode 0600, directory
0700 -- not world-readable, and Unix sockets are local-only by
construction, no network exposure). The CLI (``password-manager lock``
/ ``status`` / ``show``) connects to it to request an action.

Protocol is intentionally tiny: one-line newline-terminated commands, one
line back. No secret ever crosses this socket -- only status words like
``locked``/``unlocked`` and a JSON status blob containing non-sensitive
fields (see ``ControlServer``'s ``status_provider`` contract).
"""

from __future__ import annotations

import json
import os
import socket
import threading
from collections.abc import Callable
from pathlib import Path

_SOCK_MODE = 0o600
_DIR_MODE = 0o700


def runtime_dir() -> Path:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(xdg) if xdg else Path(f"/run/user/{os.getuid()}")
    return base / "password-manager"


def socket_path() -> Path:
    return runtime_dir() / "control.sock"


def send_command(command: str, timeout: float = 2.0) -> str | None:
    """Send a one-line command to a running UI process. Returns its
    response, or ``None`` if no UI process is currently listening (this
    is a normal, expected state -- e.g. the vault is locked and no
    window is open)."""
    path = socket_path()
    if not path.exists():
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall((command + "\n").encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", errors="replace").strip()
    except (OSError, socket.timeout):
        return None


CommandHandler = Callable[[str], str]


class ControlServer:
    """Runs inside the UI process. One background thread accepting
    connections; handlers are simple string->string callbacks supplied
    by the caller (e.g. ``"lock"`` -> session.lock(...) -> ``"ok"``)."""

    def __init__(self, handlers: dict[str, CommandHandler]) -> None:
        self._handlers = handlers
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        d = runtime_dir()
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, _DIR_MODE)
        path = socket_path()
        try:
            path.unlink()
        except FileNotFoundError:
            pass

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(path))
        os.chmod(path, _SOCK_MODE)
        srv.listen(4)
        srv.settimeout(0.5)
        self._server = srv

        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()

    def _serve_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    conn.settimeout(2.0)
                    data = b""
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    command = data.decode("utf-8", errors="replace").strip()
                    handler = self._handlers.get(command)
                    response = handler(command) if handler else "unknown_command"
                    conn.sendall(response.encode("utf-8"))
                except (OSError, socket.timeout):
                    pass

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        path = socket_path()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def status_json(**fields: object) -> str:
    """Build the one allowed status payload shape -- callers must only
    ever pass non-sensitive fields (state names, counts, booleans)."""
    return json.dumps(fields)
