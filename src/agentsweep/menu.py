"""Interactive mode: TUI arrow-key menus (with a numbered fallback).

Primary path (RAW_INPUT_AVAILABLE):
  action_menu() → source_picker() → cli.main(["scan", "--source", X])

Fallback (no tty / CI / dumb terminal):
  The classic numbered prompt (1-7) so non-tty / piped users still work.

Menu actions invoke cli.main with verb argv — zero duplicated logic, and
every action inherits the pipeline UI, safety gates, and exit codes. The
imports are lazy to avoid a cycle (cli imports this module).
"""
from __future__ import annotations

import copy
import os
import threading
from pathlib import Path

from . import __version__, ui
from .pipeline import _suggest_paths

# Menu actions that map straight to a cli verb invocation, with no extra
# control flow. Both the TUI and the numbered menu dispatch off this single
# table, so adding/retargeting an action is a one-line edit instead of a new
# branch in two parallel ladders.
_SIMPLE_ACTIONS: dict[str, list[str]] = {
    "redact": ["fix", "--source", "claude-code"],
    "undo": ["undo", "--source", "claude-code"],
    "json": ["scan", "--source", "claude-code", "--json"],
}
# Numbered-fallback keys onto the same action names.
_NUMBERED_ACTIONS: dict[str, str] = {"3": "redact", "4": "undo", "5": "json"}


def _check_updates_interactive() -> None:
    """Synchronous 'check for updates', shared by both interactive menus."""
    from .cli import check_for_update, _version_tuple

    print("  checking for updates…")
    latest, err = check_for_update(timeout=5)
    if err is not None:
        ui.warn_line(f"could not reach PyPI — {err}")
    elif _version_tuple(latest) > _version_tuple(__version__):
        print(
            f"  agentsweep {latest} is available — run: "
            f"uv tool upgrade agentsweep  (or: pip install --upgrade agentsweep)"
        )
    else:
        print(f"  agentsweep {__version__} is up to date")


def _passive_update_check() -> None:
    """Fire a background thread to check PyPI for a newer version.

    If a newer version is found within ~1 second, print a dim yellow notice.
    On timeout or any failure, print nothing.  The thread is daemonized so it
    never blocks process exit.
    """
    from .cli import check_for_update

    result: list[str | None] = [None]

    def _fetch() -> None:
        latest, err = check_for_update(timeout=2)
        if err is None:
            result[0] = latest

    t = threading.Thread(target=_fetch, daemon=True)
    t.start()
    t.join(timeout=1.0)

    if not t.is_alive() and result[0] is not None:
        from .cli import _version_tuple
        if _version_tuple(result[0]) > _version_tuple(__version__):
            ui.console.print(
                f"  [dim yellow]update available: agentsweep {result[0]} — "
                f"run: uv tool upgrade agentsweep  (or: pip install --upgrade agentsweep)[/dim yellow]"
            )


def run_menu() -> int:
    from .cli import main
    from .ui.keys import RAW_INPUT_AVAILABLE

    if ui.console.is_terminal and not os.environ.get("AGENTSWEEP_NO_ANIM"):
        ui.console.clear()
    ui.big_banner(__version__)
    _passive_update_check()
    ui.contribute_line()

    if RAW_INPUT_AVAILABLE:
        return _run_tui_menu(main)
    else:
        return _run_numbered_menu(main)


# ── TUI path ─────────────────────────────────────────────────────────────────

def _run_tui_menu(main) -> int:
    from .ui.picker import action_menu, source_picker

    while True:
        try:
            action = action_menu()
        except (KeyboardInterrupt, EOFError):
            print()
            ui.shutdown_notice()
            return 0

        if action is None or action == "quit":
            return 0

        if action == "scan":
            try:
                picks = source_picker()
            except (KeyboardInterrupt, EOFError):
                print()
                continue
            if picks is None:
                continue  # user pressed Back
            if "__all__" in picks:
                _scan_all_sources()
                _pause()
                continue
            for name in picks:
                if name == "__custom__":
                    root = _ask_folder()
                    if root is not None:
                        main(["scan", "--root", str(root)])
                else:
                    main(["scan", "--source", name])
            _pause()

        elif action in _SIMPLE_ACTIONS:
            main(_SIMPLE_ACTIONS[action])
            _pause()

        elif action == "updates":
            _check_updates_interactive()
            _pause()

        elif action == "star":
            _open_repo()
            _pause()


def _pause() -> None:
    try:
        input("\n  press Enter for the menu...")
    except (EOFError, KeyboardInterrupt):
        print()


def _open_repo() -> None:
    """Open the GitHub repo in a browser and nudge the user to contribute."""
    import webbrowser
    from . import __repo__

    star = "★" if ui._encodes(ui.console, "★") else "*"
    ui.console.print(
        f"\n  [bold yellow]{star} agentsweep is open source and built by its users.[/]")
    ui.console.print(
        "  Star it, file an issue, or add your agent / a detection rule:\n"
        f"  [yellow]{__repo__}[/]")
    try:
        if webbrowser.open(__repo__):
            ui.console.print("  [dim]opened the repo in your browser...[/]")
    except Exception:
        pass


# ── Numbered fallback (non-tty / CI / dumb terminal) ─────────────────────────

def _run_numbered_menu(main) -> int:
    while True:
        ui.menu_options()
        try:
            choice = input("  > ").strip().lower()
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            ui.shutdown_notice()
            return 0

        if choice == "1":
            _scan_all_sources()
        elif choice == "2":
            root = _ask_folder()
            if root is not None:
                main(["scan", "--root", str(root)])
        elif choice in _NUMBERED_ACTIONS:
            main(_SIMPLE_ACTIONS[_NUMBERED_ACTIONS[choice]])
        elif choice == "6":
            _check_updates_interactive()
        elif choice == "7":
            _open_repo()
        elif choice in {"8", "q", "quit", "exit"}:
            return 0
        else:
            ui.warn_line(f"unknown option: {choice!r} — pick 1-8")
            continue

        try:
            input("\n  press Enter for the menu...")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0


# ── Shared helpers ────────────────────────────────────────────────────────────

def _scan_all_sources() -> None:
    """Scan all registered sources via cli.main — no duplicated pipeline logic."""
    from .cli import main

    main(["scan", "--all"])


def _ask_folder() -> Path | None:
    """Prompt for a folder, forgivingly: suggest near-misses on typos,
    show the file count before scanning, allow up to 3 attempts."""
    for _ in range(3):
        try:
            raw = input("  folder to scan: ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not raw:
            return None
        path = Path(raw).expanduser()
        with ui.console.status(f"  [dim]scanning {path}…[/]"):
            exists = path.exists()
            count = sum(1 for _ in path.rglob("*.jsonl")) if exists else 0
        if exists:
            print(f"  found {count} .jsonl file(s) under {path}")
            if count == 0:
                try:
                    anyway = input("  scan anyway? [y/N]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return None
                if anyway != "y":
                    continue
            return path
        ui.warn_line(f"path not found: {path}")
        for hint in _suggest_paths(path):
            print(f"    did you mean: {path.parent / hint}")
    return None


def offer_redaction(args, *, source=None, found_by_file=None) -> int | None:
    """After a scan shows live secrets, offer to redact them in place.

    When source + found_by_file are supplied (cached from the first scan via
    _findings_out), calls pipeline.redact_findings() directly — skipping
    DISCOVER and SCAN entirely so the user never sees a double-scan.  Falls
    back to pipeline.run() when no cache is available.

    Returns the redaction exit code, or None if the user skipped.
    A typed REDACT confirmation is required; a blocked gate prompts once
    for a --force override.
    """
    print()
    ui.warn_line("those keys are sitting in plain text — redact them now? "
                 "(.bak backups kept; `agentsweep undo` reverts)")
    try:
        typed = input("  type REDACT to confirm (anything else cancels): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if typed != "REDACT":
        ui.warn_line("cancelled — nothing was written")
        return None

    fix_args = copy.copy(args)
    fix_args.fix = True
    fix_args.allow_production = True

    # rec captures whether the last attempt's failure was force-recoverable
    # (an active-session gate) — only then is offering --force meaningful.
    rec: list[bool] = []
    if source is not None and found_by_file is not None:
        from .pipeline import redact_findings

        def _apply(a):
            return redact_findings(a, source, found_by_file,
                                   _force_recoverable_out=rec)
    else:
        from .pipeline import run

        def _apply(a):
            return run(a, _force_recoverable_out=rec)

    code = _apply(fix_args)
    # Offer --force ONLY when the block was an active-session gate that --force
    # can bypass. For a post-redaction validation failure or a "backup already
    # exists" (already-redacted) file, --force can't help, so don't prompt.
    if code == 2 and not fix_args.force and rec and rec[-1]:
        try:
            retry = input(
                "  an active-session gate blocked the redaction (see above).\n"
                "  override with --force? Only safe if no agent session is "
                "actively writing. [y/N]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return code
        if retry == "y":
            fix_args.force = True
            return _apply(fix_args)
    return code
