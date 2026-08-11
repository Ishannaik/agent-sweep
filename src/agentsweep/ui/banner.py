"""The AGENT / SWEEP banners: small one-liner and the animated marquee.

The five-phase animation paints every frame explicitly (Live with
auto_refresh off) — the default refresh thread samples at 60Hz and drops
frames queued faster than 16.7ms, which made earlier versions look static.
"""

from __future__ import annotations

import contextlib
import os
import random
import time

from rich.console import Group
from rich.live import Live
from rich.text import Text

from .console import _encodes, console

# 5-row block font. '#' is replaced with a full block when the stream can
# render it.
_FONT = {
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "G": [" ####", "#    ", "# ###", "#   #", " ### "],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "W": ["#   #", "#   #", "# # #", "## ##", "#   #"],
    "P": ["#### ", "#   #", "#### ", "#    ", "#    "],
}
_GRADIENT = ["red", "red", "dark_orange", "orange1", "yellow"]

# Glyph pools for the decode-noise phases. Picked per-console so the
# cp1252/legacy ASCII fallback still gets the full show.
_NOISE_UNICODE = "░▒▓█▌▐▀▄"
_NOISE_ASCII = "01<>#$%&*+=/\\?^~"
_NOISE_STYLES = ("grey35", "grey46", "grey58", "dark_red", "red3")
_DECODE_ZONE = 7  # columns behind the beam where glyphs are still resolving


def _noise_pool() -> str:
    return _NOISE_UNICODE if _encodes(console, _NOISE_UNICODE) else _NOISE_ASCII


def _grad_idx(row: int) -> int:
    """Map a banner row (AGENT=0-4, blank=5, SWEEP=6-10) to a gradient index."""
    return row if row < 5 else row - 6


def _banner_rows() -> tuple[list[str], list[str]]:
    """Render AGENT / SWEEP as (lines, per-line styles).

    Cells are doubled to 2 chars wide when the terminal allows — block
    glyphs are ~1:2, so doubling makes the letters read as solid squares.
    """
    fill = "█" if _encodes(console, "█") else "#"
    cell_w = 2 if console.width >= 70 else 1
    lines: list[str] = []
    styles: list[str] = []
    for word in ("AGENT", "SWEEP"):
        for r in range(5):
            row = " ".join(_FONT[ch][r] for ch in word)
            row = "".join(c * cell_w for c in row).replace("#", fill)
            lines.append(row)
            styles.append(f"bold {_GRADIENT[r]}")
        lines.append("")
        styles.append("")
    return lines[:-1], styles[:-1]  # drop the trailing blank


def _compose(rows: list[Text], footer: Text) -> Group:
    """Stack banner rows + footer line into one Live frame."""
    return Group(Text(), *rows, Text(), footer, Text())


def _status(label: str, tick: int) -> Text:
    """Dim hacker-console status line shown under the banner mid-animation."""
    lead = "▸" if _encodes(console, "▸") else ">"
    t = Text("   ")
    t.append(f"{lead} ", style="bold red")
    t.append(f"{label}{'.' * (1 + tick % 3)}", style="dim")
    return t


def _frame_noise(
    lines: list[str],
    width: int,
    density: float,
    pool: str,
    rng: random.Random,
    footer: Text,
) -> Group:
    """Phase 1: the marque materializes out of churning glyph static."""
    rows: list[Text] = []
    for line in lines:
        t = Text("   ")
        for ch in line.ljust(width):
            if ch != " ":
                if rng.random() < density:
                    t.append(rng.choice(pool), style=rng.choice(_NOISE_STYLES))
                else:
                    t.append(" ")
            elif rng.random() < 0.03 * (1.0 - density):
                t.append(".", style="grey30")  # stray interference sparks
            else:
                t.append(" ")
        rows.append(t)
    return _compose(rows, footer)


def _frame_sweep(
    lines: list[str],
    styles: list[str],
    width: int,
    beam: int,
    bar: str,
    pool: str,
    rng: random.Random,
    footer: Text,
) -> Group:
    """Phase 2: a white scanline wipes across; glyphs behind it flicker
    through a hot decode zone before locking into the gradient letters;
    ahead of it the phase-1 static keeps churning."""
    rows: list[Text] = []
    for r, (line, style) in enumerate(zip(lines, styles)):
        color = _GRADIENT[_grad_idx(r)]
        t = Text("   ")
        for c, ch in enumerate(line.ljust(width)):
            if beam <= c < beam + 2:
                t.append(bar, style="bold white")  # the scanline itself
            elif c < beam:
                if ch == " ":
                    t.append(" ")
                elif beam - c <= 1:
                    t.append(rng.choice(pool), style="bold yellow")  # hot edge
                elif (
                    beam - c < _DECODE_ZONE and rng.random() > (beam - c) / _DECODE_ZONE
                ):
                    t.append(rng.choice(pool), style=f"bold {color}")
                else:
                    t.append(ch, style=style)
            elif ch != " " and rng.random() < 0.55:
                t.append(rng.choice(pool), style=rng.choice(_NOISE_STYLES))
            else:
                t.append(" ")
        rows.append(t)
    return _compose(rows, footer)


def _frame_glint(lines: list[str], styles: list[str], g: int, footer: Text) -> Group:
    """Phase 3: a slanted white-hot glint with yellow bloom races over the
    finished letters, one row of lag per line for a diagonal streak."""
    rows: list[Text] = []
    for r, (line, style) in enumerate(zip(lines, styles)):
        lo = g - r
        t = Text("   ")
        for c, ch in enumerate(line):
            if ch == " ":
                t.append(" ")
            elif lo <= c < lo + 2:
                t.append(ch, style="bold white")
            elif lo - 2 <= c < lo or lo + 2 <= c < lo + 4:
                t.append(ch, style="bold yellow")
            else:
                t.append(ch, style=style)
        rows.append(t)
    return _compose(rows, footer)


def _frame_shimmer(
    lines: list[str], shift: int, sparkle: bool, rng: random.Random, footer: Text
) -> Group:
    """Phase 4: the fire gradient rolls through the letters, with white
    sparkle pops on the final pass, then settles into place."""
    rows: list[Text] = []
    for r, line in enumerate(lines):
        color = _GRADIENT[(_grad_idx(r) + shift) % len(_GRADIENT)]
        t = Text("   ")
        for ch in line:
            if ch == " ":
                t.append(" ")
            elif sparkle and rng.random() < 0.04:
                t.append(ch, style="bold white")
            else:
                t.append(ch, style=f"bold {color}")
        rows.append(t)
    return _compose(rows, footer)


def _banner_frame(
    lines: list[str],
    styles: list[str],
    width: int,
    tagline: str,
    tag_chars: int | None = None,
    tag_noise: str = "",
    cursor: bool = False,
) -> Group:
    """A settled frame: full gradient letters, tagline typed to `tag_chars`
    with an optional decoding head of noise glyphs and a block cursor."""
    bar = "█" if _encodes(console, "█") else "#"
    rows: list[Text] = []
    for line, style in zip(lines, styles):
        rows.append(Text("   ") + Text(line, style=style))
    shown = tagline if tag_chars is None else tagline[:tag_chars]
    tag = Text("   ")
    tag.append(shown, style="dim")
    if tag_noise:
        tag.append(tag_noise, style="dim red")
    if cursor:
        tag.append(bar, style="bold red")
    return _compose(rows, tag)


def _animate_banner(lines: list[str], styles: list[str], tagline: str) -> None:
    """~2.8s cinematic reveal; every frame painted explicitly."""
    width = max(len(line) for line in lines)
    bar = "█" if _encodes(console, "█") else "#"
    pool = _noise_pool()
    rng = random.Random()  # nosec B311 # visual noise timing for a cinematic banner, not security-sensitive
    with Live(console=console, auto_refresh=False, transient=False) as live:

        def frame(renderable: Group, hold: float) -> None:
            live.update(renderable, refresh=True)
            time.sleep(hold)

        try:
            # Phase 1 — signal acquisition: static materializes (~0.4s).
            for i in range(12):
                f = _status("intercepting agent history stream", i // 4)
                frame(_frame_noise(lines, width, (i + 1) / 12, pool, rng, f), 0.028)
            # Phase 2 — decode sweep, 1 column per frame (~1.1s).
            for beam in range(0, width + _DECODE_ZONE + 2):
                f = _status("sweeping for exposed secrets", beam // 8)
                frame(
                    _frame_sweep(lines, styles, width, beam, bar, pool, rng, f), 0.013
                )
            # Phase 3 — diagonal glint streak (~0.3s).
            f = _status("signal locked", 0)
            for g in range(0, width + len(lines) + 6, 3):
                frame(_frame_glint(lines, styles, g, f), 0.012)
            # Phase 4 — gradient fire rolls through, then settles (~0.3s).
            for k, shift in enumerate((4, 3, 2, 1, 0, 4, 3, 2, 1, 0)):
                frame(_frame_shimmer(lines, shift, k >= 5, rng, f), 0.028)
            # Phase 5 — tagline decodes itself under a block cursor (~0.6s).
            for i in range(0, len(tagline) + 2, 2):
                shown = min(i, len(tagline))
                head = "".join(
                    rng.choice(pool) for _ in range(min(2, len(tagline) - shown))
                )
                frame(
                    _banner_frame(
                        lines,
                        styles,
                        width,
                        tagline,
                        tag_chars=shown,
                        tag_noise=head,
                        cursor=True,
                    ),
                    0.015,
                )
            for blink in (False, True, False):
                frame(_banner_frame(lines, styles, width, tagline, cursor=blink), 0.07)
        finally:
            # Always settle on the finished banner — including on Ctrl-C.
            live.update(_banner_frame(lines, styles, width, tagline), refresh=True)


def big_banner(version: str) -> None:
    """Full-size AGENT / SWEEP banner; animated scanner-sweep on real
    terminals, static art on pipes/CI or with AGENTSWEEP_NO_ANIM set."""
    lines, styles = _banner_rows()
    tagline = f"secret scanner for AI agent histories — v{version}"
    if console.is_terminal and not os.environ.get("AGENTSWEEP_NO_ANIM"):
        # Ctrl-C lands here mid-animation: the finally above has already
        # painted the settled banner, so just skip ahead — never fall
        # through to the static print (that would draw it twice).
        with contextlib.suppress(KeyboardInterrupt):
            _animate_banner(lines, styles, tagline)
        return
    console.print()
    for line, style in zip(lines, styles):
        console.print(Text("   " + line, style=style))
    console.print()
    console.print(Text(f"   {tagline}", style="dim"))
    console.print()


def banner(version: str) -> None:
    """Compact one-line banner used at the top of every pipeline run."""
    wing = "▄▄▄" if _encodes(console, "▄") else "==="
    t = Text("  ")
    t.append(f"{wing} ", style="bold red")
    t.append(f"AGENTSWEEP v{version}", style="bold")
    t.append(f" {wing}", style="bold red")
    t.append("  secret scanner for AI agent histories", style="dim")
    console.print()
    console.print(t)
    console.print()
