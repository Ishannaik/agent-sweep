"""Pipeline report widgets: stage lines, findings table, panels, menu."""

from __future__ import annotations

from pathlib import Path

from rich import box
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .console import (
    STAGE_STYLE,
    TOTAL_STAGES,
    _box,
    _encodes,
    _icons,
    _safe,
    console,
    err_console,
)


def stage(n: int, status: str, name: str, *parts: object, err: bool = False) -> None:
    """One pipeline line: `  [n/5] ✔ NAME      detail · detail`.

    soft_wrap: long details (paths) must overflow like plain print() rather
    than hard-wrap or crop at rich's assumed 80-col width on pipes.
    """
    target = err_console if err else console
    ic = _icons(target)
    sep = " · " if _encodes(target, "·") else " | "
    style = STAGE_STYLE[status]
    t = Text("  ")
    t.append(f"[{n}/{TOTAL_STAGES}] ", style="dim")
    t.append(f"{ic[status]} ", style=style)
    t.append(f"{name:<9}", style=style)
    detail = sep.join(_safe(target, p) for p in parts if str(p))
    if detail:
        t.append(" ")
        t.append(detail)
    target.print(t, soft_wrap=True)


def menu_options() -> None:
    """Numbered action menu for interactive mode."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold red", justify="right")
    grid.add_column()
    grid.add_column(style="dim")
    grid.add_row("[1]", "Scan all sources", "all 29 agents in parallel")
    grid.add_row("[2]", "Scan custom folder", "point at any directory")
    grid.add_row(
        "[3]", "Redact secrets", "run agentsweep fix (with typed REDACT confirmation)"
    )
    grid.add_row("[4]", "Undo last redaction", "restores .bak backups")
    grid.add_row("[5]", "Findings as JSON", "machine-readable")
    grid.add_row("[6]", "Check for updates", "")
    star = "★" if _encodes(console, "★") else "*"
    grid.add_row(
        "[7]",
        "Star / contribute",
        f"{star} open the repo - add your agent, file issues, PRs",
    )
    grid.add_row("[8]", "Quit", "")
    console.print(
        Padding(
            Panel(
                grid,
                title="MENU",
                title_align="left",
                border_style="red",
                box=_box(console, box.HEAVY),
                padding=(1, 2),
                expand=False,
            ),
            (0, 0, 0, 2),
        )
    )


def findings_table(rows: list[tuple[str, str, Path, int]], root: Path) -> None:
    """Red table of (rule display, masked secret, file, line).

    Cells are wrapped in Text so bracketed path segments (e.g. a Next.js
    `[id]` directory) are never parsed as rich markup — raw strings would
    silently vanish or raise MarkupError.
    """
    table = Table(
        box=_box(console, box.HEAVY_HEAD),
        border_style="red",
        header_style="bold red",
    )
    table.add_column("RULE", style="bold")
    table.add_column("SECRET (masked)", style="red")
    table.add_column("FILE")
    table.add_column("LINE", justify="right", style="dim")
    for display, masked, path, line in rows:
        table.add_row(
            Text(_safe(console, display)),
            Text(_safe(console, masked)),
            Text(_safe(console, rel(path, root))),
            str(line),
        )
    console.print(Padding(table, (0, 0, 0, 8)))


def sources_table(rows: list[dict]) -> None:
    """Table of every supported source: key, name, on-disk root, detection.

    Each row is a dict with keys ``source``, ``display``, ``experimental``,
    ``root`` and ``detected`` (matching pipeline.list_sources' payload). A
    green ``● found`` marks a root that exists on this machine; a dim ``–``
    marks one that doesn't. Cells are wrapped in Text so bracketed path
    segments are never parsed as rich markup.
    """
    ic = _icons(console)
    found = ic.get("ok", "●")
    table = Table(
        box=_box(console, box.HEAVY_HEAD),
        border_style="cyan",
        header_style="bold cyan",
    )
    table.add_column("SOURCE", style="bold")
    table.add_column("AGENT")
    table.add_column("HISTORY ROOT")
    table.add_column("ON DISK", justify="center")
    for r in rows:
        name = r["display"]
        if r.get("experimental"):
            name += " (experimental)"
        if r.get("detected"):
            mark = Text(f"{found} found", style="green")
        else:
            mark = Text("–", style="dim")
        table.add_row(
            Text(_safe(console, r["source"])),
            Text(_safe(console, name)),
            Text(_safe(console, r["root"]), style="dim"),
            mark,
        )
    console.print(Padding(table, (0, 0, 0, 2)))
    detected = sum(1 for r in rows if r.get("detected"))
    warn_line(
        f"{detected} of {len(rows)} source(s) have history on this "
        f"machine — scan one with:  agentsweep scan --source <SOURCE>"
    )


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def redact_row(status: str, path_display: str, note: str = "") -> None:
    """Per-file result under the REDACT stage. ok→stdout, skip/fail→stderr."""
    target = console if status == "ok" else err_console
    ic = _icons(target)
    label = {"ok": "OK", "skip": "SKIP", "fail": "FAIL"}[status]
    t = Text("        ")
    t.append(f"{ic[status]} {label:<5}", style=STAGE_STYLE[status])
    t.append(_safe(target, path_display))
    if note:
        t.append(f"  {_safe(target, note)}", style="dim")
    target.print(t, soft_wrap=True)


def rotation_panel(items: list[tuple[str, str]]) -> None:
    """Red double-border ACTION REQUIRED panel: (rule, rotation guidance).

    Body is a two-column grid so guidance that wraps keeps a hanging
    indent instead of snapping back to the panel edge.
    """
    ic = _icons(console)
    grid = Table.grid(padding=0)
    grid.add_column(width=2)
    grid.add_column()
    for rule, guidance in items:
        grid.add_row("", Text(_safe(console, rule), style="bold red"))
        grid.add_row("  ", Text(_safe(console, guidance)))
    grid.add_row("", "")
    grid.add_row(
        "",
        Text(
            "Redaction removes the secret from local history,\n"
            "but the key still works until you rotate it.",
            style="dim",
        ),
    )
    console.print(
        Padding(
            Panel(
                grid,
                title=f"{ic['warn']} ACTION REQUIRED — rotate these secrets now",
                title_align="left",
                border_style="bold red",
                box=_box(console, box.DOUBLE),
                padding=(0, 1),
                expand=False,
            ),
            (0, 0, 0, 8),
        )
    )


def gate_panel(title: str, lines: list[str]) -> None:
    """Yellow safety-gate refusal panel on stderr.

    On a non-terminal stream (tests, CI greps) emit plain unwrapped lines:
    a Panel honors COLUMNS even when piped, and wrapping could split the
    exact phrases callers grep for.
    """
    ic = _icons(err_console)
    if not err_console.is_terminal:
        for line in [f"{ic['warn']} {title}"] + lines:
            err_console.print(Text(_safe(err_console, line)), soft_wrap=True)
        return
    body = Text("\n".join(_safe(err_console, line) for line in lines))
    err_console.print(
        Padding(
            Panel(
                body,
                title=f"{ic['warn']} {title}",
                title_align="left",
                border_style="bold yellow",
                box=_box(err_console, box.DOUBLE),
                padding=(0, 1),
                expand=False,
            ),
            (0, 0, 0, 2),
        )
    )


def warn_line(message: str) -> None:
    ic = _icons(err_console)
    err_console.print(
        Text(f"  {ic['warn']} {_safe(err_console, message)}", style="yellow"),
        soft_wrap=True,
    )


def contribute_line() -> None:
    """A one-line nudge: agentsweep is open source, shaped by its users.

    Never called on --json / non-tty paths (callers gate on that), so
    machine output stays clean.
    """
    from .. import __repo__

    star = "★" if _encodes(console, "★") else "*"
    t = Text("  ")
    t.append(f"{star} ", style="bold yellow")
    t.append("agentsweep is open source, built by its users - ", style="dim")
    t.append("star it & add your agent: ", style="dim")
    t.append(_safe(console, __repo__), style="yellow")
    console.print(t)
