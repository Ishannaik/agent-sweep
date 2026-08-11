# PYTHON_ARGCOMPLETE_OK
"""Entry point: verb dispatch and flag parsing.

Usage shapes, all supported:

    agentsweep                 bare → interactive menu (on a real terminal)
    agentsweep scan [opts]     scan only
    agentsweep scan --all      scan every registered agent (aggregate report)
    agentsweep scan --all --detected
                               scan only agents whose history root exists
    agentsweep fix  [opts]     redact (guided + confirmed on a terminal)
    agentsweep fix --all       redact every agent with findings, one at a time
                               (each source gated + confirmed separately)
    agentsweep undo [opts]     restore .bak backups
    agentsweep purge [opts]    delete .bak backups (after rotating the keys)
    agentsweep list-sources    list supported agents + which are on this machine
    agentsweep explain <id>    print a rule's pattern + rotation guidance
    agentsweep explain --list  print every known rule id
    agentsweep --fix ...       legacy flag form, kept working as an alias
    agentsweep --update        check PyPI for a newer version

Run logic lives in pipeline.py; interaction in menu.py.
"""

from __future__ import annotations

import argparse
import json
import string
import sys
import threading
from pathlib import Path

from . import __version__

VERBS = {"scan", "fix", "undo", "purge"}

_PYPI_URL = "https://pypi.org/pypi/agentsweep/json"


def _sources() -> dict:
    """Lazy accessor for the SOURCES registry (avoids import cost on -V)."""
    from .sources import SOURCES

    return SOURCES


def check_for_update(timeout: int = 2) -> tuple[str | None, str | None]:
    """Return (latest_version, error_message).

    Fetches PyPI metadata synchronously.  On any failure returns
    (None, error_string) so the caller can decide whether to surface it.
    """
    import urllib.request

    try:
        with urllib.request.urlopen(_PYPI_URL, timeout=timeout) as resp:  # nosec B310 # _PYPI_URL is a hardcoded https:// constant, never user input
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


def _validate_redact_template(value: str) -> str:
    """Reject a --redact-with template that would corrupt the written file
    or crash mid-redaction, before any scanning starts.

    {rule} is optional (the default template uses it, but a fixed string
    like "[SECRET]" is valid too). Anything else in braces is not: this
    parses the template the same way str.format() would (string.Formatter,
    not a regex) but only allows an exact, bare "rule" field — no
    conversion (!r), no format spec (:>10), no attribute/index access
    (.foo, [0]) — since those can raise mid-format (e.g. AttributeError,
    which plain str.format(rule="x") probing wouldn't always catch: "x"
    happens to have most of str's own attributes).
    """
    if not value:
        # An empty template silently no-ops via `redact_with or REDACT_TEMPLATE`
        # in pipeline.py, but even if it didn't: an empty replacement erases
        # all trace that a secret was ever there, defeating the point of a
        # redaction tool (no marker means no signal anything was scrubbed).
        raise argparse.ArgumentTypeError("--redact-with must not be empty")
    if "/" in value or "\\" in value:
        raise argparse.ArgumentTypeError(
            "--redact-with must not contain path separators (/ or \\)"
        )
    # U+0085 (NEL), U+2028 (LINE SEPARATOR), and U+2029 (PARAGRAPH SEPARATOR)
    # are >= 0x20 so the control-character check above doesn't catch them,
    # but str.splitlines() treats all three as line breaks and
    # json.dumps(..., ensure_ascii=False) writes them through raw — one of
    # these in the template silently turns one JSON value into two lines,
    # which fails safe_write's post-write line-count validation and aborts
    # the redaction after the secret has already been found (but not fixed).
    _EXTRA_LINE_BREAK_CODEPOINTS = (0x85, 0x2028, 0x2029)
    if any(
        ord(c) < 0x20 or ord(c) == 0x7F or ord(c) in _EXTRA_LINE_BREAK_CODEPOINTS
        for c in value
    ):
        raise argparse.ArgumentTypeError(
            "--redact-with must not contain control or line-breaking characters"
        )
    try:
        fields = list(string.Formatter().parse(value))
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"--redact-with has an invalid {{placeholder}}: {e}"
        ) from e
    for _literal, field_name, format_spec, conversion in fields:
        if field_name is None:
            continue
        if field_name != "rule" or format_spec or conversion is not None:
            raise argparse.ArgumentTypeError(
                "--redact-with only supports a bare {rule} placeholder "
                "(no conversion, format spec, attribute, or index access)"
            )
    return value


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
        if getattr(args, "format", None):
            return
        if not sys.stdout.isatty():
            return
    except Exception:
        return

    done = threading.Event()
    result: list[str | None] = [None]  # mutable box for thread result

    def _fetch() -> None:
        import urllib.request

        try:
            with urllib.request.urlopen(_PYPI_URL, timeout=1.5) as resp:  # nosec B310 # _PYPI_URL is a hardcoded https:// constant, never user input
                data = json.loads(resp.read())
            result[0] = data["info"]["version"]
        except Exception:  # nosec B110 # best-effort background version check; any network/parse error must not crash the main flow
            pass
        finally:
            done.set()

    t = threading.Thread(target=_fetch, daemon=True)
    t.start()

    # Wait up to 0.8 s for the background thread before proceeding.
    done.wait(timeout=0.8)

    latest = result[0]
    if latest is not None and _version_tuple(latest) > _version_tuple(__version__):
        from . import ui

        # Route through the shared console so NO_COLOR / --no-color are honored
        # (a raw ANSI print would bypass apply_no_color entirely).
        ui.console.print(
            f"  ★ agentsweep {latest} available — pip install --upgrade agentsweep",
            style="dim yellow",
        )


def _run_update_check() -> int:
    """Implement the --update flag: print result, return exit code."""
    latest, err = check_for_update()
    if err is not None:
        print(f"  warning: could not reach PyPI — {err}", file=sys.stderr)
        return 0
    if latest is not None and _version_tuple(latest) > _version_tuple(__version__):
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
        from . import ui

        return sys.stdin.isatty() and ui.console.is_terminal
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

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

    # Honor NO_COLOR / --no-color before any styled output (menu, banner,
    # update notice). The flag is parsed per-verb below; catch it here too so
    # it applies to the interactive menu and the early --version/--update paths.
    from . import ui

    ui.apply_no_color(ui.resolve_no_color("--no-color" in argv))

    try:
        import argcomplete

        completion_parser = _get_completion_parser()
        argcomplete.autocomplete(completion_parser)
    except ImportError:
        pass

    # Dispatched here (after completion setup), not alongside -V/--update/
    # list-sources above: explain is a normal, occasionally-invoked verb, not
    # a hot path like --version, so it can afford this setup cost — and doing
    # so is what lets rule_id_completer actually fire for shell completion.
    if argv and argv[0] == "explain":
        return _run_explain(argv[1:])

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
        # Merged in from a config file (--no-color wasn't itself passed): the
        # earlier apply_no_color() call above only saw raw argv/env, so layer
        # the config-derived value on top. One-directional, so this is a
        # no-op if color was already stripped.
        if args.no_color:
            ui.apply_no_color(True)
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
        from . import ui

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
    ap.add_argument(
        "--source",
        choices=list(_sources()),
        default="claude-code",
        help="Which agent's history (default: claude-code).",
    )
    ap.add_argument(
        "--root", type=Path, help="Override the source's default root directory."
    )


def _parse_run(verb: str, rest: list[str]) -> argparse.Namespace:
    from .scanner import DETECTOR_IDS, RULES

    ap = argparse.ArgumentParser(
        prog=f"agentsweep {verb}",
        description="Find and redact secrets in AI coding agent histories.",
    )
    # default=None so we can tell "user passed --source" from the implicit
    # default when validating mutual exclusion with --all.
    ap.add_argument(
        "--source",
        choices=list(_sources()),
        default=None,
        help="Which agent's history (default: claude-code).",
    )
    ap.add_argument(
        "--root", type=Path, help="Override the source's default root directory."
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="Every registered agent source: scan aggregates "
        "findings; fix redacts each source in turn, gated "
        "and confirmed separately.",
    )
    ap.add_argument(
        "--detected",
        action="store_true",
        help="With --all, only scan sources whose history root "
        "exists on this machine (same signal as "
        "list-sources --detected).",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write findings as JSON to this file instead of flooding the terminal.",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON to stdout (no banner/styling).",
    )
    ap.add_argument(
        "--report",
        action="store_true",
        help="Include blast-radius report in JSON output (implies --json).",
    )
    ap.add_argument(
        "--stats",
        action="store_true",
        help="Include a findings summary (total, per-rule, and for --all per-source).",
    )
    ap.add_argument(
        "--no-color",
        action="store_true",
        default=None,
        help="Disable ANSI colors/styling in human output "
        "(also honored via the NO_COLOR env var).",
    )
    ap.add_argument(
        "--format",
        choices=["sarif", "human"],
        help="Emit findings in an interchange format instead of "
        "the default report: sarif = SARIF 2.1.0 for GitHub "
        "code scanning and SARIF viewers (scan only). Pass "
        "'human' to force the default report even when a "
        'config file sets format = "sarif".',
    )
    ap.add_argument(
        "--no-ignore",
        action="store_true",
        default=None,
        help="Ignore any .agentsweepignore files.",
    )
    ap.add_argument(
        "--ignore",
        action="store_true",
        help="Force .agentsweepignore suppression on, even if a "
        "config file sets no_ignore = true.",
    )
    ap.add_argument(
        "--exclude-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Suppress findings from this rule id. Repeatable.",
    )
    ap.add_argument(
        "--only-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Keep only findings from this rule id. Repeatable.",
    )
    # Redaction flags (used by `fix` / legacy --fix; harmless on `scan`).
    ap.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip .bak file creation (NOT recommended).",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Bypass soft safety checks (mtime, running-process).",
    )
    ap.add_argument(
        "--allow-production",
        action="store_true",
        help="Allow --fix against the default production root.",
    )
    ap.add_argument(
        "--redact-with",
        type=_validate_redact_template,
        default=None,
        metavar="TEMPLATE",
        help="Custom placeholder for redacted secrets, e.g. '[SECRET]'. "
        "{rule} is substituted if present. Default: [REDACTED:{rule}]",
    )
    args = ap.parse_args(rest)
    args.fix = verb == "fix"

    from .config import load_config

    cfg = load_config()
    if args.source is None and "source" in cfg and not args.all:
        args.source = cfg["source"]
    if args.no_color is None and "no_color" in cfg:
        args.no_color = cfg["no_color"]
    if (
        args.format is None
        and "format" in cfg
        and verb != "fix"
        and not args.json
        and not args.report
    ):
        args.format = cfg["format"]
    if args.no_ignore is None and "no_ignore" in cfg:
        args.no_ignore = cfg["no_ignore"]

    if args.source is not None and args.source not in _sources():
        ap.error(f"argument --source: invalid choice from config file: {args.source!r}")
    if args.format is not None and args.format not in ("sarif", "human"):
        ap.error(f"argument --format: invalid choice from config file: {args.format!r}")

    # "human" is a CLI-only override that forces the default report even when
    # a config file sets format = "sarif" — resolve it to the same "no format"
    # state as never having set one, before it reaches any downstream check.
    if args.format == "human":
        args.format = None

    args.no_color = bool(args.no_color)
    args.no_ignore = bool(args.no_ignore)
    # --ignore is the CLI-only override for a config file's no_ignore = true —
    # the config-set flags need a way back to the built-in default, same as
    # --format human does for a config-set format.
    if getattr(args, "ignore", False):
        args.no_ignore = False

    if args.exclude_rule and args.only_rule:
        ap.error("cannot use --exclude-rule with --only-rule")

    all_rule_ids = {rule_id for rule_id, _display, _pattern in RULES} | set(
        DETECTOR_IDS
    )
    unknown = sorted(
        set(args.exclude_rule).union(args.only_rule).difference(all_rule_ids)
    )
    if unknown:
        joined = ", ".join(unknown)
        ap.error(f"unknown rule id(s): {joined} (see: agentsweep explain --list)")

    args.exclude_rule = set(args.exclude_rule)
    args.only_rule = set(args.only_rule)

    if args.format is not None:
        if args.json:
            ap.error("cannot use --json with --format sarif; pick one output format")
        if args.fix:
            ap.error("--format is a scan output format; not valid with fix")

    if getattr(args, "report", False):
        if args.fix:
            ap.error("--report is a scan output option; not valid with fix")
        if args.format is not None:
            ap.error(
                "cannot use --report with --format sarif; blast-radius is JSON-only"
            )
        # Contract: --report always emits machine JSON (with blast_radius).
        args.json = True

    if args.all:
        if args.source is not None:
            ap.error("cannot use --source with --all")
        if args.root is not None:
            ap.error("cannot use --root with --all")
        # Placeholder so any code that still reads args.source is safe.
        args.source = "claude-code"
    else:
        if args.detected:
            ap.error(
                "--detected requires --all (or use: agentsweep list-sources --detected)"
            )
        if args.source is None:
            args.source = "claude-code"
    return args


def _parse_list_sources(rest: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="agentsweep list-sources",
        description="List every supported agent source and whether its "
        "history root exists on this machine. Read-only.",
    )
    ap.add_argument(
        "--json", action="store_true", help="Emit the source list as JSON to stdout."
    )
    ap.add_argument(
        "--detected",
        action="store_true",
        help="Show only sources whose history root exists here.",
    )
    return ap.parse_args(rest)


def _parse_explain(rest: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="agentsweep explain",
        description="Print a detection rule's display name, pattern, and "
        "rotation guidance. Read-only; touches no files, needs "
        "no --source/--root.",
    )
    ap.add_argument(
        "rule_id",
        nargs="?",
        help="Rule id to explain, e.g. stripe-live. See --list for all ids.",
    )
    ap.add_argument(
        "--list",
        action="store_true",
        help="Print every known rule id, one per line "
        "(pipe into --exclude-rule/--only-rule if those land).",
    )
    args = ap.parse_args(rest)
    if not args.list and not args.rule_id:
        ap.error("rule_id is required unless --list is given")
    return args


def _run_explain(rest: list[str]) -> int:
    """Implement `agentsweep explain`: read-only lookup into scanner.RULES /
    scanner.ROTATION_GUIDANCE / scanner.DETECTOR_IDS. No file access."""
    args = _parse_explain(rest)

    from .scanner import DETECTOR_IDS, ROTATION_GUIDANCE, RULES

    if args.list:
        all_ids = sorted(
            {rule_id for rule_id, _display, _pattern in RULES} | set(DETECTOR_IDS)
        )
        for rule_id in all_ids:
            print(rule_id)
        return 0

    rule_id = args.rule_id

    for rid, display, pattern in RULES:
        if rid == rule_id:
            print(f"{display} ({rid})")
            print(f"pattern: {pattern.pattern}")
            print(f"rotation guidance: {ROTATION_GUIDANCE.get(rid, '(none recorded)')}")
            return 0

    if rule_id in DETECTOR_IDS:
        print(f"{rule_id} (function-based detector — no static regex pattern)")
        print(f"rotation guidance: {ROTATION_GUIDANCE.get(rule_id, '(none recorded)')}")
        return 0

    print(
        f"error: unknown rule id {rule_id!r} (see: agentsweep explain --list)",
        file=sys.stderr,
    )
    return 2


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
    ap.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt (required when not running on a terminal).",
    )
    return ap.parse_args(rest)


def source_completer(prefix: str, **kwargs) -> list[str]:
    """Dynamically complete --source values from the SOURCES registry."""
    return [s for s in _sources() if s.startswith(prefix)]


def rule_id_completer(prefix: str, **kwargs) -> list[str]:
    """Dynamically complete rule ids for `explain` from scanner's registries."""
    from .scanner import DETECTOR_IDS, RULES

    all_ids = sorted(
        {rule_id for rule_id, _display, _pattern in RULES} | set(DETECTOR_IDS)
    )
    return [rule_id for rule_id in all_ids if rule_id.startswith(prefix)]


def _with_source_completer(action: argparse.Action) -> argparse.Action:
    setattr(action, "completer", source_completer)
    return action


def _with_rule_id_completer(action: argparse.Action) -> argparse.Action:
    # setattr, not `action.completer = ...`: argparse.Action has no `completer`
    # in typeshed, so direct assignment fails mypy. Same dodge as above.
    setattr(action, "completer", rule_id_completer)
    return action


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
    scan_source = scan_p.add_argument(
        "--source",
        choices=list(_sources()),
        default=None,
        help="Which agent's history (default: claude-code).",
    )
    _with_source_completer(scan_source)
    scan_p.add_argument(
        "--root", type=Path, help="Override the source's default root directory."
    )
    scan_p.add_argument(
        "--all", action="store_true", help="Scan every registered agent source."
    )
    scan_p.add_argument(
        "--detected",
        action="store_true",
        help="Only scan sources whose history root exists.",
    )
    scan_p.add_argument(
        "-o", "--output", type=Path, help="Write findings as JSON to this file."
    )
    scan_p.add_argument(
        "--json", action="store_true", help="Emit findings as JSON to stdout."
    )
    scan_p.add_argument(
        "--report",
        action="store_true",
        help="Include blast-radius report in JSON output (implies --json).",
    )
    scan_p.add_argument(
        "--stats",
        action="store_true",
        help="Include a findings summary (total, per-rule, and for --all per-source).",
    )
    scan_p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors/styling in human output.",
    )
    scan_p.add_argument(
        "--no-ignore", action="store_true", help="Ignore any .agentsweepignore files."
    )
    _with_rule_id_completer(
        scan_p.add_argument(
            "--exclude-rule",
            action="append",
            default=[],
            metavar="RULE_ID",
            help="Suppress findings from this rule id. Repeatable.",
        )
    )
    _with_rule_id_completer(
        scan_p.add_argument(
            "--only-rule",
            action="append",
            default=[],
            metavar="RULE_ID",
            help="Keep only findings from this rule id. Repeatable.",
        )
    )
    scan_p.add_argument(
        "--no-backup", action="store_true", help="Skip .bak file creation."
    )
    scan_p.add_argument("--force", action="store_true", help="Bypass safety checks.")
    scan_p.add_argument(
        "--allow-production",
        action="store_true",
        help="Allow against default production root.",
    )
    scan_p.add_argument(
        "--redact-with",
        type=_validate_redact_template,
        default=None,
        metavar="TEMPLATE",
        help="Custom placeholder for redacted secrets, e.g. '[SECRET]'. "
        "{rule} is substituted if present. Default: [REDACTED:{rule}]",
    )

    # fix
    fix_p = subparsers.add_parser("fix", description="Redact secrets in history.")
    fix_source = fix_p.add_argument(
        "--source",
        choices=list(_sources()),
        default=None,
        help="Which agent's history (default: claude-code).",
    )
    _with_source_completer(fix_source)
    fix_p.add_argument(
        "--root", type=Path, help="Override the source's default root directory."
    )
    fix_p.add_argument(
        "--all",
        action="store_true",
        help="Redact every agent source with findings, one at a time.",
    )
    fix_p.add_argument(
        "--detected",
        action="store_true",
        help="With --all, only sources whose history root exists.",
    )
    fix_p.add_argument(
        "-o", "--output", type=Path, help="Write findings as JSON to this file."
    )
    fix_p.add_argument(
        "--json", action="store_true", help="Emit findings as JSON to stdout."
    )
    fix_p.add_argument(
        "--stats",
        action="store_true",
        help="Include a findings summary (total, per-rule, and for --all per-source).",
    )
    fix_p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors/styling in human output.",
    )
    fix_p.add_argument(
        "--no-ignore", action="store_true", help="Ignore any .agentsweepignore files."
    )
    _with_rule_id_completer(
        fix_p.add_argument(
            "--exclude-rule",
            action="append",
            default=[],
            metavar="RULE_ID",
            help="Suppress findings from this rule id. Repeatable.",
        )
    )
    _with_rule_id_completer(
        fix_p.add_argument(
            "--only-rule",
            action="append",
            default=[],
            metavar="RULE_ID",
            help="Keep only findings from this rule id. Repeatable.",
        )
    )
    fix_p.add_argument(
        "--no-backup", action="store_true", help="Skip .bak file creation."
    )
    fix_p.add_argument("--force", action="store_true", help="Bypass safety checks.")
    fix_p.add_argument(
        "--allow-production",
        action="store_true",
        help="Allow against default production root.",
    )
    fix_p.add_argument(
        "--redact-with",
        type=_validate_redact_template,
        default=None,
        metavar="TEMPLATE",
        help="Custom placeholder for redacted secrets, e.g. '[SECRET]'. "
        "{rule} is substituted if present. Default: [REDACTED:{rule}]",
    )

    # undo
    undo_p = subparsers.add_parser("undo", description="Restore backups.")
    undo_source = undo_p.add_argument(
        "--source",
        choices=list(_sources()),
        default="claude-code",
        help="Which agent's history.",
    )
    _with_source_completer(undo_source)
    undo_p.add_argument(
        "--root", type=Path, help="Override the source's default root directory."
    )

    # purge
    purge_p = subparsers.add_parser("purge", description="Delete backups.")
    purge_source = purge_p.add_argument(
        "--source",
        choices=list(_sources()),
        default="claude-code",
        help="Which agent's history.",
    )
    _with_source_completer(purge_source)
    purge_p.add_argument(
        "--root", type=Path, help="Override the source's default root directory."
    )
    purge_p.add_argument(
        "--yes", action="store_true", help="Skip the confirmation prompt."
    )

    # list-sources
    ls_p = subparsers.add_parser(
        "list-sources", description="List supported agent sources."
    )
    ls_p.add_argument(
        "--json", action="store_true", help="Emit the source list as JSON to stdout."
    )
    ls_p.add_argument(
        "--detected",
        action="store_true",
        help="Show only sources whose history root exists.",
    )

    # explain
    explain_p = subparsers.add_parser(
        "explain",
        description="Print a rule's display name, pattern, and rotation guidance.",
    )
    _with_rule_id_completer(
        explain_p.add_argument(
            "rule_id", nargs="?", help="Rule id to explain (see --list)."
        )
    )
    explain_p.add_argument(
        "--list", action="store_true", help="Print every known rule id."
    )

    # completion
    comp_p = subparsers.add_parser(
        "completion", description="Generate shell completion scripts."
    )
    comp_p.add_argument(
        "shell",
        choices=["bash", "zsh", "fish", "powershell"],
        help="The shell to generate completions for.",
    )

    return ap


def _parse_completion(rest: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="agentsweep completion",
        description="Generate shell completion scripts for agentsweep.",
    )
    ap.add_argument(
        "shell",
        choices=["bash", "zsh", "fish", "powershell"],
        help="The shell to generate completions for.",
    )
    return ap.parse_args(rest)


def _run_completion(rest: list[str]) -> int:
    args = _parse_completion(rest)
    try:
        from argcomplete import shellcode
    except ImportError:
        print("  error: argcomplete is not installed.", file=sys.stderr)
        print("  Install it using: pip install argcomplete", file=sys.stderr)
        return 2

    print(shellcode(["agentsweep", "asweep"], shell=args.shell))  # nosec B604 # argcomplete.shellcode's own "target shell" kwarg (choices=bash/zsh/fish/powershell), not subprocess shell=True
    return 0


if __name__ == "__main__":
    sys.exit(main())
