"""Per-file scan progress: live bar on terminals, silent no-op on pipes."""
from __future__ import annotations

import os
import time
from collections import deque
from types import TracebackType
from typing import Literal

from rich.live import Live
from rich.progress import TaskID

from .console import _encodes, _safe, console
from ..tips import tip_for

# Maximum recent detections shown in the live feed.
_MAX_FEED = 6

# Rotate to a new tip every this many seconds.
_TIP_INTERVAL = 7

# How long the found-count stays flashed after a new detection.
_FLASH_SECS = 0.4


def _flash_style(t: float) -> str:
    """Found-count colour for flash progress `t`: 0.0 (just hit, white) →
    1.0 (settled red). Linear white→red3 fade; rich downgrades the rgb to
    the nearest ANSI on non-truecolor terminals."""
    t = min(max(t, 0.0), 1.0)
    r = int(255 - (255 - 215) * t)
    g = int(255 - (255 - 40) * t)
    b = int(255 - (255 - 40) * t)
    return f"bold rgb({r},{g},{b})"


class _FlashHeader:
    """The '⚡ N secrets found' line, rendered fresh on every Live refresh so
    the flash fades on the clock — not only when a file advances."""

    def __init__(self, progress: "_RichScanProgress"):
        self._p = progress

    def __rich__(self):
        from rich.text import Text

        p = self._p
        bolt = p._lightning()
        header = Text("        ")
        if p._hits == 0:
            header.append(f"{bolt} scanning…", style="dim")
            return header
        t = (time.monotonic() - p._flash_time) / _FLASH_SECS
        style = _flash_style(t)
        header.append(f"{bolt} ", style=style)
        header.append(str(p._hits), style=style)
        noun = "secret" if p._hits == 1 else "secrets"
        header.append(f" {noun} found", style=style)
        return header


class _NullScanProgress:
    """No-op progress for pipes/CI — keeps the call sites unconditional."""

    def __enter__(self) -> "_NullScanProgress":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        return False

    def advance(self, current: str) -> None:
        pass

    def detection(self, rule_display: str, masked: str, location: str) -> None:
        pass


class _RichScanProgress:
    """Live per-file progress bar + detection feed for the SCAN phase.

    Renders a rich Live group:
      - header counter line  ("⚡ N secrets found")
      - rolling feed of the last _MAX_FEED detections
      - the SCAN progress bar with the current file

    transient=True (the Live is created with transient=True): the whole
    group vanishes when the context exits so the pipeline's SCAN stage line
    takes its place cleanly.
    """

    def __init__(self, total: int):
        from rich.progress import (
            BarColumn, MofNCompleteColumn, Progress, TaskProgressColumn,
            TextColumn, TimeElapsedColumn,
        )
        self._progress = Progress(
            TextColumn("        "),
            TextColumn("SCAN", style="bold cyan"),
            BarColumn(bar_width=28, complete_style="red",
                      finished_style="bold green"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.fields[current]}", style="dim"),
            console=console,
            # Progress is embedded inside a Live; don't auto-start/stop.
            auto_refresh=False,
        )
        self._total = total
        self._task: TaskID | None = None
        self._hits: int = 0
        self._feed: deque[tuple[str, str, str]] = deque(maxlen=_MAX_FEED)
        self._live: Live | None = None
        self._start_time: float = 0.0
        self._flash_time: float = 0.0  # monotonic ts of the last detection

    # ------------------------------------------------------------------ render

    def _lightning(self) -> str:
        """⚡ if the stream can encode it, else '!'."""
        return "⚡" if _encodes(console, "⚡") else "!"

    def _bullet(self) -> str:
        return "▸" if _encodes(console, "▸") else ">"

    def _build_renderable(self):
        """Build the full Group for one Live frame."""
        from rich.console import Group
        from rich.text import Text

        parts: list[object] = []

        # ── header ──────────────────────────────────────────────────────────
        # Self-rendering so the flash fades on the Live clock, not per-file.
        parts.append(_FlashHeader(self))

        # ── detection feed ───────────────────────────────────────────────────
        feed_list = list(self._feed)
        n = len(feed_list)
        bullet = self._bullet()
        for i, (rule, masked, loc) in enumerate(feed_list):
            age = n - 1 - i          # 0 = newest
            dim_factor = age / max(n, 1)

            line = Text("        ")
            # dim out older entries slightly
            if dim_factor > 0.6:
                line.append(f"  {bullet} ", style="dim")
                line.append(_safe(console, rule), style="dim")
                line.append("  ", style="dim")
                line.append(_safe(console, masked), style="dim red")
                line.append(f"  {_safe(console, loc)}", style="dim")
            elif dim_factor > 0.3:
                line.append(f"  {bullet} ", style="")
                line.append(_safe(console, rule), style="bold")
                line.append("  ", style="")
                line.append(_safe(console, masked), style="red")
                line.append(f"  {_safe(console, loc)}", style="dim")
            else:
                # newest: fully lit
                line.append(f"  {bullet} ", style="bold red")
                line.append(_safe(console, rule), style="bold")
                line.append("  ", style="")
                line.append(_safe(console, masked), style="bold red")
                line.append(f"  {_safe(console, loc)}", style="dim")
            parts.append(line)

        # Pad to keep the progress bar from jumping up and down.
        for _ in range(_MAX_FEED - n):
            parts.append(Text(""))

        # ── progress bar ─────────────────────────────────────────────────────
        parts.append(self._progress)

        # ── rotating tip ────────────────────────────────────────────────────
        elapsed = time.monotonic() - self._start_time if self._start_time else 0.0
        tip_index = int(elapsed / _TIP_INTERVAL)
        tip_text = Text("        ")
        tip_text.append("Tip: ", style="dim")
        tip_text.append(_safe(console, tip_for(tip_index)), style="dim")
        parts.append(tip_text)

        return Group(*parts)

    # ------------------------------------------------------------------ ctx mgr

    def __enter__(self) -> "_RichScanProgress":
        self._start_time = time.monotonic()
        self._task = self._progress.add_task(
            "scan", total=self._total, current="")
        live = Live(
            self._build_renderable(),
            console=console,
            transient=True,
            refresh_per_second=14,
            auto_refresh=True,
        )
        self._live = live
        live.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        if self._live is None:
            return False
        self._live.__exit__(exc_type, exc, tb)
        return False

    # ------------------------------------------------------------------ API

    def advance(self, current: str) -> None:
        if self._task is None:
            return
        self._progress.update(
            self._task, advance=1, current=_safe(console, current))
        if self._live is not None:
            self._live.update(self._build_renderable())

    def detection(self, rule_display: str, masked: str, location: str) -> None:
        """Record a secret hit and refresh the live feed immediately."""
        self._hits += 1
        self._flash_time = time.monotonic()
        self._feed.append((rule_display, masked, location))
        if self._live is not None:
            self._live.update(self._build_renderable())


def scan_progress(n_files: int):
    """Per-file progress bar on real terminals; silent no-op otherwise."""
    if console.is_terminal and not os.environ.get("AGENTSWEEP_NO_ANIM"):
        return _RichScanProgress(n_files)
    return _NullScanProgress()
