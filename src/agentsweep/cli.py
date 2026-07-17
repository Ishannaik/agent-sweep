# PYTHON_ARGCOMPLETE_OK
"""Entry point: verb dispatch and flag parsing.

Usage shapes, all supported:

    agentsweep                 bare → interactive menu (on a real terminal)
    agentsweep scan [opts]     scan only
    agentsweep scan --all      scan every registered agent (aggregate report)
    agentsweep scan --all --detected
                               scan only agents whose history root exists
    agentsweep fix  [opts]     redact (guided + confirmed on a terminal)
    agentsweep undo [opts]     restore .bak backups
    agentsweep purge [opts]    delete .bak backups (after rotating the keys)
    agentsweep list-sources    list supported agents + which are on this machine
    agentsweep --fix ...       legacy flag form, kept working as an alias
    agentsweep --update        check PyPI for a newer version

Run logic lives in pipeline.py; interaction in menu.py.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import urllib.request
from pathlib import Path

from . import __version__, ui
from .sources import SOURCES

VERBS = {"scan", "fix", "undo", "purge"}

_PYPI_URL = "https://pypi.org/pypi/agentsweep/json"


def check_for_update(timeout: int = 2) -> tuple[str | None, str | None]:
    """Return (latest_version, error_message).

    Fetches PyPI metadata synchronously.  On any failure returns
    (None, error_string) so the caller can decide whether to surface it.
    """
    try:
        with urllib.request.urlopen(_PYPI_URL, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return data["info"]["version"], None
    except Exception as exc:  # network error, JSON error, key error, …
        return None, str(exc)


def _version_tuple(v: str) -> tuple[int, ...]:
    """Convert "1.2.3" to (1, 2, 3) for numeric comparison."""
    try:
        return tuple(int(x) for x in v.split(".") if x.isdigit())
    except Exception:
        return (0,)


def _background_update_notice(args: argparse.Namespace) -> None:
    """Fire a background update check and print a notice before first output.

    Starts a daemon thread that fetches PyPI with a 1.5 s timeout.  The main
    thread waits at most 0.8 s for the result; if the thread hasn't finished
    by then we proceed regardless (the thread is still a daemon so it won't
    block process exit).

    Skipped entirely when:
    - ``args.json`` is True (machine-readable output must stay clean), or
    - stdout is not a tty (piped / redirected).
    """
    # Guard: skip in non-interactive / machine-readable contexts, or when the
    # user has explicitly opted out via env var (useful in CI / slow networks).
    import os
    try:
        if os.environ.get("AGENTSWEEP_NO_UPDATE"):
            return
        if getattr(args, "json", False):
            return
        if not sys.stdout.isatty():
            return
    except Exception:
        return

    done = threading.Event()
    result: list[str | None] = [None]  # mutable box for thread result

    def _fetch() -> None:
        try:
            with urllib.request.urlopen(_PYPI_URL, timeout=1.5) as resp:
                data = json.loads(resp.read())
            result[0] = data["info"]["version"]
        except Exception:
            pass
        finally:
            done.set()

    t = threading.Thread(target=_fetch, daemon=True)
    t.start()

    # Wait up to 0.8 s for the background thread before proceeding.
    done.wait(timeout=0.8)

    latest = result[0]
    if latest is not None and _version_tuple(latest) > _version_tuple(__version__):
        # Print a single dim-yellow notice before any other output.
        print(
            f"\033[2;33m  ★ agentsweep {latest} available"
            f" — pip install --upgrade agentsweep\033[0m"
        )


def _run_update_check() -> int:
    """Implement the --update flag: print result, return exit code."""
    latest, err = check_for_update()
    if err is not None:
        print(f"  warning: could not reach PyPI — {err}", file=sys.stderr)
        return 0
    if _version_tuple(latest) > _version_tuple(__version__):
        print(
            f"  agentsweep {latest} is available — run: "
            f"pip install --upgrade agentsweep"
        )
    else:
        print(f"  agentsweep {__version__} is up to date")
    return 0


def _interactive() -> bool:
    """True when a human is at both ends (stdin tty + terminal stdout)."""
    try:
        return sys.stdin.isatty() and ui.console.is_terminal
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    try:
        import argcomplete
        completion_parser = _get_completion_parser()
        argcomplete.autocomplete(completion_parser)
    except ImportError:
        pass

    if argv and argv[0] in ("-V", "--version"):
        print(f"agentsweep {__version__}")
        return 0

    if argv and argv[0] in ("--update",):
        return _run_update_check()

    if argv and argv[0] == "list-sources":
        from .pipeline import list_sources
        return list_sources(_parse_list_sources(argv[1:]))

    if argv and argv[0] == "completion":
        return _run_completion(argv[1:])

    if not argv and _interactive():
        from .menu import run_menu
        try:
            return run_menu()
        except KeyboardInterrupt:
            ui.shutdown_notice()
            return 130

    verb, rest = _route(argv)

    try:
        if verb == "undo":
            from .pipeline import undo
            return undo(_parse_undo(rest))

        if verb == "purge":
            from .pipeline import purge
            return purge(_parse_purge(rest))

        args = _parse_run(verb, rest)
        _background_update_notice(args)
        from .pipeline import run, run_all
        from .menu import offer_redaction

        # Multi-source scan is read-only and has no interactive redact offer
        # (fix stays per-source). Dispatch before the single-source path.
        if getattr(args, "all", False):
            return run_all(args)

        if verb == "fix" and not _interactive():
            args.fix = True  # script path: explicit gate flags required
            return run(args)

        # Interactive scan OR interactive fix: scan first, then offer to
        # redact what we found. One guided path; the offer is the fix.
        findings_out: list = []
        args.fix = False
        code = run(args, _findings_out=findings_out)
        if code == 1 and not args.json and _interactive():
            src, fbf = findings_out[0] if findings_out else (None, None)
            fixed = offer_redaction(args, source=src, found_by_file=fbf)
            if fixed is not None:
                return fixed
        return code
    except KeyboardInterrupt:
        ui.shutdown_notice(during_fix=(verb == "fix"), plain=("--json" in rest))
        return 130


def _route(argv: list[str]) -> tuple[str, list[str]]:
    """Resolve (verb, remaining args), accepting both verbs and legacy flags."""
    if argv and argv[0] in VERBS:
        return argv[0], argv[1:]
    # Legacy flag form: --fix means the fix verb; otherwise scan.
    if "--fix" in argv:
        return "fix", [a for a in argv if a != "--fix"]
    return "scan", argv


def _add_common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--source", choices=list(SOURCES), default="claude-code",
                    help="Which agent's history (default: claude-code).")
    ap.add_argument("--root", type=Path,
                    help="Override the source's default root directory.")


def _parse_run(verb: str, rest: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog=f"agentsweep {verb}",
        description="Find and redact secrets in AI coding agent histories.",
    )
    # default=None so we can tell "user passed --source" from the implicit
    # default when validating mutual exclusion with --all.
    ap.add_argument("--source", choices=list(SOURCES), default=None,
                    help="Which agent's history (default: claude-code).")
    ap.add_argument("--root", type=Path,
                    help="Override the source's default root directory.")
    ap.add_argument("--all", action="store_true",
                    help="Scan every registered agent source and aggregate "
                         "findings (scan only; not valid with fix).")
    ap.add_argument("--detected", action="store_true",
                    help="With --all, only scan sources whose history root "
                         "exists on this machine (same signal as "
                         "list-sources --detected).")
    ap.add_argument("-o", "--output", type=Path,
                    help="Write findings as JSON to this file instead of "
                         "flooding the terminal.")
    ap.add_argument("--json", action="store_true",
                    help="Emit findings as JSON to stdout (no banner/styling).")
    ap.add_argument("--format", choices=["sarif"],
                    help="Emit findings in an interchange format instead of "
                         "the default report: sarif = SARIF 2.1.0 for GitHub "
                         "code scanning and SARIF viewers (scan only).")
    ap.add_argument("--no-ignore", action="store_true",
                    help="Ignore any .agentsweepignore files.")
    # Redaction flags (used by `fix` / legacy --fix; harmless on `scan`).
    ap.add_argument("--no-backup", action="store_true",
                    help="Skip .bak file creation (NOT recommended).")
    ap.add_argument("--force", action="store_true",
                    help="Bypass soft safety checks (mtime, running-process).")
    ap.add_argument("--allow-production", action="store_true",
                    help="Allow --fix against the default production root.")
    args = ap.parse_args(rest)
    args.fix = (verb == "fix")

    if args.format is not None:
        if args.json:
            ap.error("cannot use --json with --format sarif; pick one output "
                     "format")
        if args.fix:
            ap.error("--format is a scan output format; not valid with fix")

    if args.all:
        if args.source is not None:
            ap.error("cannot use --source with --all")
        if args.root is not None:
            ap.error("cannot use --root with --all")
        if args.fix:
            ap.error(
                "fix --all is not supported; "
                "run: agentsweep fix --source <name>"
            )
        # Placeholder so any code that still reads args.source is safe.
        args.source = "claude-code"
    else:
        if args.detected:
            ap.error("--detected requires --all "
                     "(or use: agentsweep list-sources --detected)")
        if args.source is None:
            args.source = "claude-code"
    return args


def _parse_list_sources(rest: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="agentsweep list-sources",
        description="List every supported agent source and whether its "
                    "history root exists on this machine. Read-only.",
    )
    ap.add_argument("--json", action="store_true",
                    help="Emit the source list as JSON to stdout.")
    ap.add_argument("--detected", action="store_true",
                    help="Show only sources whose history root exists here.")
    return ap.parse_args(rest)


def _parse_undo(rest: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="agentsweep undo",
        description="Restore *.jsonl.bak backups over their redacted files.",
    )
    _add_common(ap)
    return ap.parse_args(rest)


def _parse_purge(rest: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="agentsweep purge",
        description="Delete *.bak backups once the leaked keys are rotated. "
                    "The backups hold the pre-redaction originals, so this "
                    "is permanent — `agentsweep undo` stops working for "
                    "them.",
    )
    _add_common(ap)
    ap.add_argument("--yes", action="store_true",
                    help="Skip the confirmation prompt (required when not "
                         "running on a terminal).")
    return ap.parse_args(rest)


def source_completer(prefix: str, **kwargs) -> list[str]:
    """Dynamically complete --source values from the SOURCES registry."""
    return [s for s in SOURCES if s.startswith(prefix)]


def _get_completion_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="agentsweep",
        description="Find and redact secrets in AI coding agent histories.",
    )
    ap.add_argument("-V", "--version", action="store_true")
    ap.add_argument("--update", action="store_true")

    subparsers = ap.add_subparsers(dest="subcommand")

    # scan
    scan_p = subparsers.add_parser("scan", description="Scan history files.")
    scan_source = scan_p.add_argument("--source", choices=list(SOURCES), default=None,
                                      help="Which agent's history (default: claude-code).")
    scan_source.completer = source_completer
    scan_p.add_argument("--root", type=Path, help="Override the source's default root directory.")
    scan_p.add_argument("--all", action="store_true", help="Scan every registered agent source.")
    scan_p.add_argument("--detected", action="store_true", help="Only scan sources whose history root exists.")
    scan_p.add_argument("-o", "--output", type=Path, help="Write findings as JSON to this file.")
    scan_p.add_argument("--json", action="store_true", help="Emit findings as JSON to stdout.")
    scan_p.add_argument("--no-ignore", action="store_true", help="Ignore any .agentsweepignore files.")
    scan_p.add_argument("--no-backup", action="store_true", help="Skip .bak file creation.")
    scan_p.add_argument("--force", action="store_true", help="Bypass safety checks.")
    scan_p.add_argument("--allow-production", action="store_true", help="Allow against default production root.")

    # fix
    fix_p = subparsers.add_parser("fix", description="Redact secrets in history.")
    fix_source = fix_p.add_argument("--source", choices=list(SOURCES), default=None,
                                     help="Which agent's history (default: claude-code).")
    fix_source.completer = source_completer
    fix_p.add_argument("--root", type=Path, help="Override the source's default root directory.")
    fix_p.add_argument("-o", "--output", type=Path, help="Write findings as JSON to this file.")
    fix_p.add_argument("--json", action="store_true", help="Emit findings as JSON to stdout.")
    fix_p.add_argument("--no-ignore", action="store_true", help="Ignore any .agentsweepignore files.")
    fix_p.add_argument("--no-backup", action="store_true", help="Skip .bak file creation.")
    fix_p.add_argument("--force", action="store_true", help="Bypass safety checks.")
    fix_p.add_argument("--allow-production", action="store_true", help="Allow against default production root.")

    # undo
    undo_p = subparsers.add_parser("undo", description="Restore backups.")
    undo_source = undo_p.add_argument("--source", choices=list(SOURCES), default="claude-code",
                                       help="Which agent's history.")
    undo_source.completer = source_completer
    undo_p.add_argument("--root", type=Path, help="Override the source's default root directory.")

    # purge
    purge_p = subparsers.add_parser("purge", description="Delete backups.")
    purge_source = purge_p.add_argument("--source", choices=list(SOURCES), default="claude-code",
                                         help="Which agent's history.")
    purge_source.completer = source_completer
    purge_p.add_argument("--root", type=Path, help="Override the source's default root directory.")
    purge_p.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")

    # list-sources
    ls_p = subparsers.add_parser("list-sources", description="List supported agent sources.")
    ls_p.add_argument("--json", action="store_true", help="Emit the source list as JSON to stdout.")
    ls_p.add_argument("--detected", action="store_true", help="Show only sources whose history root exists.")

    # completion
    comp_p = subparsers.add_parser("completion", description="Generate shell completion scripts.")
    comp_p.add_argument("shell", choices=["bash", "zsh", "fish", "powershell"],
                        help="The shell to generate completions for.")

    return ap


def _parse_completion(rest: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="agentsweep completion",
        description="Generate shell completion scripts for agentsweep.",
    )
    ap.add_argument("shell", choices=["bash", "zsh", "fish", "powershell"],
                    help="The shell to generate completions for.")
    return ap.parse_args(rest)


def _run_completion(rest: list[str]) -> int:
    args = _parse_completion(rest)
    try:
        from argcomplete import shellcode
    except ImportError:
        print("  error: argcomplete is not installed.", file=sys.stderr)
        print("  Install it using: pip install argcomplete", file=sys.stderr)
        return 2

    print(shellcode(["agentsweep", "asweep"], shell=args.shell))
    return 0


if __name__ == "__main__":
    sys.exit(main())
