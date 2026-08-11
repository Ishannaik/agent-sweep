"""Cross-platform single-keypress reader for the interactive TUI.

No Rich imports — pure input. The caller's event loop calls read_key()
and dispatches on the returned constant.

RAW_INPUT_AVAILABLE is probed once at import; callers gate the TUI on it.
"""

from __future__ import annotations

import sys

# Key constants returned by read_key()
UP = "UP"
DOWN = "DOWN"
ENTER = "ENTER"
SPACE = "SPACE"
QUIT = "QUIT"
OTHER = "OTHER"


def _read_key_windows() -> str:
    import msvcrt

    ch = msvcrt.getwch()
    if ch in ("\x00", "\xe0"):
        # Arrow keys: second byte distinguishes
        ch2 = msvcrt.getwch()
        if ch2 == "H":
            return UP
        if ch2 == "P":
            return DOWN
        return OTHER
    if ch in ("\r", "\n"):
        return ENTER
    if ch == " ":
        return SPACE
    if ch in ("\x1b", "q", "Q"):
        return QUIT
    return OTHER


def _read_key_unix() -> str:
    import os
    import tty
    import termios
    import select

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        # Read at the raw fd level with os.read, NOT sys.stdin.read. Python's
        # buffered stdin drains the whole escape sequence into a userspace
        # buffer on the first read, so a later select() on the fd reports "no
        # more input" and every arrow key gets misread as a bare ESC (quit).
        # os.read keeps the fd and select() in agreement.
        ch = os.read(fd, 1)
        if ch == b"\x1b":
            ready, _, _ = select.select([fd], [], [], 0.05)
            if not ready:
                return QUIT  # bare ESC key
            # Drain the rest of the sequence. Arrows are ESC [ A/B (CSI) or
            # ESC O A/B (SS3, sent in application-cursor-key mode, e.g. some
            # GNOME/xterm configs).
            rest = os.read(fd, 6)
            if rest in (b"[A", b"OA"):
                return UP
            if rest in (b"[B", b"OB"):
                return DOWN
            return OTHER  # other escape sequence (F-keys, Home, …); ignore
        if ch in (b"\r", b"\n"):
            return ENTER
        if ch == b" ":
            return SPACE
        if ch in (b"q", b"Q"):
            return QUIT
        return OTHER
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def read_key() -> str:
    """Block until a keypress and return a key constant."""
    if sys.platform == "win32":
        return _read_key_windows()
    return _read_key_unix()


def _probe() -> bool:
    """True when raw key input is available (real tty + libs present)."""
    if not sys.stdin.isatty():
        return False
    if sys.platform == "win32":
        try:
            import msvcrt  # noqa: F401

            return True
        except ImportError:
            return False
    try:
        import tty  # noqa: F401
        import termios  # noqa: F401
        import select  # noqa: F401

        return True
    except ImportError:
        return False


RAW_INPUT_AVAILABLE: bool = _probe()
