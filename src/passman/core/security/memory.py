"""Best-effort in-memory secret handling.

Honest limitation (documented per the project brief, not glossed over):
CPython gives no guaranteed secure-erase primitive for ``str``. Strings
are immutable and interned/copied by the interpreter in ways this module
cannot fully control; a ``str`` holding a password may leave copies in
memory (GC-managed, possibly relocated, possibly left in freed-but-not-
overwritten heap pages) that this code cannot reach. ``bytearray`` *is*
mutable, so it can genuinely be overwritten in place -- that is the one
real guarantee this module provides. If you need OS-level guaranteed
wiping (mlock, guard pages), Python is the wrong language; that tradeoff
was accepted when choosing this stack, consistent with the pattern
already documented in password-template-generator's README.

Practical mitigations actually applied:
- Secrets are moved into ``bytearray`` as early as possible and the
  original ``str`` reference is dropped so it becomes eligible for GC
  immediately (not a guarantee, but it minimizes the number of live
  copies and their lifetime).
- ``SecretBytes.wipe()`` overwrites the buffer in place before dropping it.
- ``__repr__``/``__str__`` never render the contents, so accidental
  logging, exception tracebacks, or REPL echoing cannot leak the value.
"""

from __future__ import annotations


class SecretBytes:
    """A mutable, wipeable holder for secret bytes.

    Not a cryptographic guarantee -- see module docstring -- but strictly
    better than passing plain ``str``/``bytes`` around, both of which are
    immutable and cannot be overwritten.
    """

    __slots__ = ("_buf", "_wiped")

    def __init__(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._buf = bytearray(data)
        self._wiped = False

    def __len__(self) -> int:
        return len(self._buf)

    def __bool__(self) -> bool:
        return not self._wiped and len(self._buf) > 0

    def to_str(self) -> str:
        if self._wiped:
            raise ValueError("SecretBytes has already been wiped.")
        return self._buf.decode("utf-8")

    def to_bytes(self) -> bytes:
        if self._wiped:
            raise ValueError("SecretBytes has already been wiped.")
        return bytes(self._buf)

    def wipe(self) -> None:
        """Overwrite the backing buffer with zeros in place."""
        if self._wiped:
            return
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._wiped = True

    def __enter__(self) -> "SecretBytes":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.wipe()

    def __repr__(self) -> str:  # never render contents
        return f"SecretBytes(len={len(self._buf)}, wiped={self._wiped})"

    __str__ = __repr__


def wipe_str_best_effort(_value: str) -> None:
    """No-op placeholder documenting that plain ``str`` secrets cannot be
    wiped in CPython. Call sites should prefer ``SecretBytes`` instead;
    this function exists only so call sites that must temporarily hold a
    ``str`` (e.g. a GTK ``Gtk.Entry`` buffer) have a single documented
    place acknowledging the limitation rather than silently doing
    nothing. Always pair with clearing the widget/reference immediately
    after use.
    """
    return None
