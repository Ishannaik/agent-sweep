"""Arrow-key driven interactive picker widgets.

action_menu()   — top-level action chooser (Scan / Redact / Undo / etc.)
source_picker() — multi-select source chooser with a Run Scan button.

Both use Rich Live for rendering and consume keys from ui.keys.read_key().
They return plain data (strings / lists) and never call the pipeline.
"""

from __future__ import annotations

from typing import Literal, overload

from rich import box
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .console import _box, _encodes, _safe, console
from . import keys as _keys


# ── helpers ─────────────────────────────────────────────────────────────────


def _check(selected: bool, target: "console") -> str:  # type: ignore[valid-type]
    if _encodes(target, "✓"):
        return "✓" if selected else " "
    return "x" if selected else " "


@overload
def _run_menu(
    title: str,
    rows: list[tuple[str, str]],
    *,
    multi: Literal[False] = False,
    button_idx: int | None = None,
    footer: str = "↑↓ move  Enter select  q quit",
) -> int | None: ...


@overload
def _run_menu(
    title: str,
    rows: list[tuple[str, str]],
    *,
    multi: Literal[True],
    button_idx: int | None = None,
    footer: str = "↑↓ move  Enter select  q quit",
) -> tuple[set[int], bool] | None: ...


def _run_menu(
    title: str,
    rows: list[tuple[str, str]],
    *,
    multi: bool = False,
    button_idx: int | None = None,
    footer: str = "↑↓ move  Enter select  q quit",
) -> int | tuple[set[int], bool] | None:
    """Generic picker loop.

    Single-select (multi=False): returns the chosen row index, or None for quit.
    Multi-select (multi=True): returns (set_of_checked_indices, run_pressed), or None.
    button_idx: if set, ENTER on that row triggers "Run" rather than toggle.
    """
    focus = 0
    checked: set[int] = set()
    n = len(rows)

    def _build() -> Panel:
        grid = Table.grid(padding=(0, 1))
        grid.add_column(width=3, justify="center")
        grid.add_column()
        grid.add_column(style="dim")

        for i, (label, hint) in enumerate(rows):
            focused = i == focus
            is_btn = i == button_idx

            if focused:
                row_style = "bold white on red"
            elif is_btn:
                row_style = "bold red"
            else:
                row_style = "white"

            if multi and not is_btn:
                ch = _check(i in checked, console)
                pfx = Text(f"[{ch}]", style="bold red" if i in checked else "dim")
            elif is_btn:
                pfx = Text(
                    "►", style="bold red" if not focused else "bold white on red"
                )
            else:
                pfx = Text("", style="")

            grid.add_row(
                pfx,
                Text(_safe(console, label), style=row_style),
                Text(_safe(console, hint), style="dim"),
            )

        return Panel(
            Padding(grid, (0, 0)),
            title=f"[bold red]{_safe(console, title)}[/]",
            title_align="left",
            border_style="red",
            box=_box(console, box.HEAVY),
            padding=(1, 2),
            expand=False,
            subtitle=f"[dim]{_safe(console, footer)}[/]",
            subtitle_align="left",
        )

    try:
        with Live(
            _build(), console=console, refresh_per_second=30, transient=False
        ) as live:
            while True:
                live.update(_build())
                try:
                    key = _keys.read_key()
                except Exception:
                    return None

                if key == _keys.UP:
                    focus = (focus - 1) % n
                elif key == _keys.DOWN:
                    focus = (focus + 1) % n
                elif key == _keys.QUIT:
                    return None
                elif key in (_keys.ENTER, _keys.SPACE):
                    if multi:
                        if button_idx is not None and focus == button_idx:
                            return (checked, True)
                        else:
                            if focus in checked:
                                checked.discard(focus)
                            else:
                                checked.add(focus)
                    else:
                        return focus
    except Exception:
        return None


# ── Public widgets ────────────────────────────────────────────────────────────

_ACTION_ROWS: list[tuple[str, str]] = [
    ("Scan history", "read-only — find secrets"),
    ("Redact secrets", "asks to confirm · .bak backups"),
    ("Undo last redaction", "restores .bak backups"),
    ("Findings as JSON", "read-only · machine-readable"),
    ("Check for updates", ""),
    ("Star / contribute", "★ open the repo — add your agent, PRs welcome"),
    ("Quit", ""),
]

_ACTION_KEYS = ["scan", "redact", "undo", "json", "updates", "star", "quit"]


def action_menu() -> str | None:
    """Show the top-level action menu. Returns action key or None (quit)."""
    result = _run_menu(
        "AGENTSWEEP",
        _ACTION_ROWS,
        multi=False,
        footer="↑↓ move  Enter select  q quit",
    )
    if result is None:
        return None
    return _ACTION_KEYS[result]


def source_picker() -> list[str] | None:
    """Show the multi-select source picker.

    Returns a list of selected source name strings (may include "__custom__")
    or None if the user pressed Back/Q.
    """
    from ..sources import SOURCES  # late import: avoids top-level cycle

    source_entries: list[tuple[str, str]] = [
        (
            SOURCES[k].display_name
            + (
                "  (experimental)" if getattr(SOURCES[k], "experimental", False) else ""
            ),
            k,
        )
        for k in SOURCES
    ]
    # "All sources" first, then each source, then Custom folder + Run Scan button.
    rows: list[tuple[str, str]] = (
        [
            ("All sources", "scan every agent in parallel"),
        ]
        + [(display, key) for display, key in source_entries]
        + [
            ("Custom folder…", "scan a specific directory"),
            ("[ Run Scan ]", ""),
        ]
    )
    source_keys = ["__all__"] + list(SOURCES.keys()) + ["__custom__"]
    button_idx = len(rows) - 1

    result = _run_menu(
        "SELECT SOURCES",
        rows,
        multi=True,
        button_idx=button_idx,
        footer="↑↓ move  Space toggle  Enter=run  q back",
    )
    if result is None:
        return None

    checked_indices, _ = result
    selected = [source_keys[i] for i in sorted(checked_indices) if i < len(source_keys)]
    # Default: claude-code if nothing selected
    if not selected:
        selected = ["claude-code"]
    return selected
