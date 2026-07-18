"""Graceful Ctrl-C farewell: dissolve outro on a tty, one line on pipes."""
from __future__ import annotations

import contextlib
import os
import random
import time

from rich.live import Live
from rich.text import Text

from .banner import _noise_pool
from .console import _icons, _safe, err_console


def _animate_shutdown(message: str) -> None:
    """~0.4s farewell: the message locks in left-to-right out of red noise."""
    pool = _noise_pool()
    rng = random.Random()  # nosec B311 # visual noise timing for a farewell animation, not security-sensitive
    ic = _icons(err_console)
    with Live(console=err_console, auto_refresh=False, transient=True) as live:
        steps = 14
        for s in range(steps + 1):
            locked = int(len(message) * s / steps)
            t = Text("  ")
            t.append(f"{ic['warn']} ", style="bold yellow")
            t.append(message[:locked], style="bold red")
            for ch in message[locked:]:
                t.append(rng.choice(pool) if ch != " " else " ",
                         style="dark_red")
            live.update(t, refresh=True)
            time.sleep(0.028)


def shutdown_notice(during_fix: bool = False, plain: bool = False) -> None:
    """Graceful Ctrl-C farewell.

    Animated dissolve on a tty; a single stderr line on pipes/CI or in
    --json mode. A second Ctrl-C mid-outro skips straight to the static
    line — never make an impatient interrupt wait.
    """
    ic = _icons(err_console)
    if (not plain and err_console.is_terminal
            and not os.environ.get("AGENTSWEEP_NO_ANIM")):
        with contextlib.suppress(KeyboardInterrupt):
            _animate_shutdown("sweep interrupted — shutting down clean")
    err_console.print(Text(
        _safe(err_console, f"  {ic['warn']} interrupted — sweep aborted cleanly"),
        style="bold yellow"), soft_wrap=True)
    if during_fix:
        err_console.print(Text(_safe(
            err_console,
            "    writes are atomic — no file was left torn; finished files "
            "keep their .bak backups"), style="dim"), soft_wrap=True)
