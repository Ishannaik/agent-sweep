"""The 5-stage scan/redact pipeline: DISCOVER → SCAN → FINDINGS → REDACT → ROTATE.

Owns all run orchestration and the --json/exit-code contracts. cli.py
parses flags and hands the parsed namespace to run(); ui owns rendering.
"""
from __future__ import annotations

import difflib
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import __version__, ui
from . import ignore as ignore_mod
from .preflight import is_agent_running, is_production_root
from .redactor import SafetyError, safe_write, safety_check
from .scanner import ROTATION_GUIDANCE, Finding, scan_text
from .sources import SOURCES, Source


REDACT_TEMPLATE = "[REDACTED:{rule}]"

# Above this many findings, a human-mode table is capped and the full set
# is written to a report file so a 900-file scan can't bury the scrollback.
MAX_TABLE_ROWS = 40
# Above this many findings, `--json` to a real terminal auto-saves to a
# file instead of flooding stdout.
JSON_FLOOD_LIMIT = 30
DEFAULT_JSON_NAME = "agentsweep-findings.json"
DEFAULT_REPORT_NAME = "agentsweep-report.txt"


def _opt(args, name: str, default=None):
    """Tolerate namespaces from older call sites that lack new fields."""
    return getattr(args, name, default)


def run(args, *, _findings_out: list | None = None) -> int:
    """Execute one scan (and optional redact) run. Exit codes:
    0 clean · 1 findings (scan-only) · 2 gate-blocked, write error, or bad path.

    When _findings_out is provided and args.fix is False, appends
    (source, found_by_file) to it so the caller can pass pre-computed
    findings to offer_redaction(), avoiding a double-scan on REDACT.
    """
    source_cls = SOURCES[args.source]
    source: Source = source_cls(root=args.root) if args.root else source_cls()
    output: Path | None = _opt(args, "output")

    if args.root is not None and not source.root.exists():
        print(f"Path not found: {source.root}", file=sys.stderr)
        for hint in _suggest_paths(source.root):
            print(f"  did you mean: {source.root.parent / hint}", file=sys.stderr)
        if args.json:
            print("[]")  # stdout stays parseable JSON even on user error
        return 2

    if not args.json:
        ui.banner(__version__)

    if not args.json:
        files: list[Path] = []
        with ui.console.status("") as status:
            for f in source.iter_files():
                files.append(f)
                status.update(
                    f"[dim]Discovering[/] [bold]{source.root}[/bold]"
                    f" … [yellow]{len(files):,}[/] file(s)"
                )
    else:
        files = list(source.iter_files())
    if not files:
        print(f"No history files found under {source.root}", file=sys.stderr)
        if args.json:
            print("[]")  # stdout must stay parseable JSON in every --json run
        else:
            ui.stage(1, "warn", "DISCOVER", source.name,
                     f"no history files under {source.root}", err=True)
        return 0

    ignores = (ignore_mod.IgnoreSet() if _opt(args, "no_ignore")
               else ignore_mod.load([source.root, Path.cwd()]))

    if args.json:
        found_by_file, _, suppressed = _scan(source, files, ignores)
        return _output_json(found_by_file, source, output, suppressed)

    ui.stage(1, "ok", "DISCOVER", source.name, f"{len(files)} file(s)", source.root)

    t0 = time.perf_counter()
    with ui.scan_progress(len(files)) as progress:
        found_by_file, strings_scanned, suppressed = _scan(
            source, files, ignores, progress)
    elapsed = time.perf_counter() - t0

    ui.stage(2, "ok", "SCAN", f"{len(files)} file(s)",
             f"{strings_scanned} string(s)", f"{elapsed:.1f}s")

    if suppressed:
        ui.warn_line(f"{suppressed} finding(s) suppressed by .agentsweepignore")

    if not found_by_file:
        ui.stage(3, "ok", "FINDINGS", "no secrets found")
        ui.stage(4, "skip", "REDACT", "nothing to redact")
        ui.stage(5, "skip", "ROTATE", "nothing to rotate")
        return 0

    total = sum(len(v) for v in found_by_file.values())
    ui.stage(3, "fail", "FINDINGS", f"{total} secret(s) in {len(found_by_file)} file(s)")
    _show_findings(found_by_file, source, output)

    if not args.fix:
        ui.stage(4, "skip", "REDACT",
                 "skipped — run with --fix to redact in place (.bak backups)")
        ui.stage(5, "warn", "ROTATE", "these keys are still live")
        ui.rotation_panel(_rotation_items(found_by_file))
        if _findings_out is not None:
            _findings_out.append((source, found_by_file))
        return 1

    gate_err = _preflight_gates(source, source_cls, args)
    if gate_err is not None:
        # The user who most needs rotation guidance is the one we just
        # refused to redact for — the keys are confirmed live.
        ui.stage(5, "warn", "ROTATE", "these keys are still live")
        ui.rotation_panel(_rotation_items(found_by_file))
        return gate_err

    rows, errors = _redact_all(
        source=source,
        found_by_file=found_by_file,
        backup=not args.no_backup,
        force=args.force,
    )

    ok_count = sum(1 for status, _, _ in rows if status == "ok")
    if errors == 0:
        ui.stage(4, "ok", "REDACT", f"{ok_count}/{len(rows)} file(s) rewritten")
    elif ok_count:
        ui.stage(4, "warn", "REDACT", f"{ok_count}/{len(rows)} file(s) rewritten")
    else:
        ui.stage(4, "fail", "REDACT", f"0/{len(rows)} file(s) rewritten")
    for status, path_display, note in rows:
        ui.redact_row(status, path_display, note)

    if ok_count:
        ui.stage(5, "warn", "ROTATE", "redacted locally", "keys live until rotated")
    else:
        ui.stage(5, "warn", "ROTATE", "nothing redacted", "these keys are still live")
    ui.rotation_panel(_rotation_items(found_by_file))

    return 0 if errors == 0 else 2


def redact_findings(args, source: Source, found_by_file: dict) -> int:
    """Apply REDACT + ROTATE using pre-computed findings; skip DISCOVER + SCAN.

    Called from offer_redaction() when the first scan cached its results via
    _findings_out, so the user never sees the pipeline restart from scratch.
    Exit codes: 0 clean, 2 gate-blocked or write error.
    """
    source_cls = SOURCES[args.source]
    gate_err = _preflight_gates(source, source_cls, args)
    if gate_err is not None:
        ui.stage(5, "warn", "ROTATE", "these keys are still live")
        ui.rotation_panel(_rotation_items(found_by_file))
        return gate_err

    rows, errors = _redact_all(
        source=source,
        found_by_file=found_by_file,
        backup=not args.no_backup,
        force=args.force,
    )
    ok_count = sum(1 for status, _, _ in rows if status == "ok")
    if errors == 0:
        ui.stage(4, "ok", "REDACT", f"{ok_count}/{len(rows)} file(s) rewritten")
    elif ok_count:
        ui.stage(4, "warn", "REDACT", f"{ok_count}/{len(rows)} file(s) rewritten")
    else:
        ui.stage(4, "fail", "REDACT", f"0/{len(rows)} file(s) rewritten")
    for status, path_display, note in rows:
        ui.redact_row(status, path_display, note)

    if ok_count:
        ui.stage(5, "warn", "ROTATE", "redacted locally", "keys live until rotated")
    else:
        ui.stage(5, "warn", "ROTATE", "nothing redacted", "these keys are still live")
    ui.rotation_panel(_rotation_items(found_by_file))
    return 0 if errors == 0 else 2


def _suggest_paths(missing: Path) -> list[str]:
    """Typo forgiveness: close-matching sibling directory names."""
    parent = missing.parent
    try:
        if not parent.exists():
            return []
        siblings = [p.name for p in parent.iterdir() if p.is_dir()]
    except OSError:
        return []
    return difflib.get_close_matches(missing.name, siblings, n=3, cutoff=0.5)


def _scan(source, files, ignores, progress=None):
    """Scan all files, wiring the progress bar + live detection feed when a
    progress object is supplied. (A multiprocessing path was evaluated and
    dropped — on Windows the spawn + per-worker regex recompile cost gave
    ~1.1x and risked a re-import fork bomb; see docs/PERF.md.)"""
    def _on_file(f: Path) -> None:
        if progress is not None:
            progress.advance(ui.rel(f, source.root))

    det = getattr(progress, "detection", None) if progress is not None else None

    def _on_finding(fd: Finding) -> None:
        if det is not None:
            det(fd.display, fd.masked, f"{ui.rel(fd.file, source.root)}:{fd.line}")

    return _scan_all(source, files, ignores=ignores,
                     on_file=_on_file, on_finding=_on_finding)


def _scan_file(
    source: Source,
    f: Path,
    ignores,
) -> tuple[Path, list[tuple[int, list, str, Finding]], int, int]:
    """Scan a single file; safe to call from a thread pool worker.

    Returns (path, findings_list, strings_scanned, suppressed_count).
    Callbacks are NOT invoked here — the caller dispatches them on the main
    thread after each future completes, so Rich Live is never touched from a
    worker thread.
    """
    items: list[tuple[int, list, str, Finding]] = []
    strings_scanned = 0
    suppressed = 0
    relpath = ui.rel(f, source.root)
    for line_num, keypath, value in source.iter_strings(f):
        strings_scanned += 1
        for finding in scan_text(value):
            finding.file = f
            finding.line = line_num
            finding.keypath = keypath
            if ignores:
                fp = ignore_mod.fingerprint(relpath, line_num, finding.rule)
                if ignores.matches(finding.rule, finding.value, fp):
                    suppressed += 1
                    continue
            items.append((line_num, keypath, value, finding))
    return f, items, strings_scanned, suppressed


# Maximum parallel workers for file scanning.  Chosen empirically: beyond
# ~8 the marginal gain on local SSDs disappears while lock contention grows.
# The constant is also kept small enough that the thread pool spins up/down
# within the lifetime of a normal scan.
_SCAN_WORKERS = 8


def _scan_all(
    source: Source,
    files: list[Path],
    ignores=None,
    on_file=None,
    on_finding=None,
) -> tuple[dict[Path, list[tuple[int, list, str, Finding]]], int, int]:
    out: dict[Path, list[tuple[int, list, str, Finding]]] = {}
    strings_scanned = 0
    suppressed = 0

    # For tiny workloads the thread-pool overhead exceeds the I/O overlap
    # benefit; fall back to the sequential path for ≤4 files.
    if len(files) <= 4:
        for f in files:
            if on_file is not None:
                on_file(f)
            _, items, sc, sup = _scan_file(source, f, ignores)
            strings_scanned += sc
            suppressed += sup
            for entry in items:
                out.setdefault(f, []).append(entry)
                if on_finding is not None:
                    on_finding(entry[3])
        return out, strings_scanned, suppressed

    workers = min(_SCAN_WORKERS, len(files))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_scan_file, source, f, ignores): f
            for f in files
        }
        for fut in as_completed(futures):
            f, items, sc, sup = fut.result()
            strings_scanned += sc
            suppressed += sup
            if on_file is not None:
                on_file(f)
            for entry in items:
                out.setdefault(f, []).append(entry)
                if on_finding is not None:
                    on_finding(entry[3])
    return out, strings_scanned, suppressed


def _table_rows(found_by_file: dict) -> list[tuple[str, str, Path, int]]:
    rows: list[tuple[str, str, Path, int]] = []
    for path, items in found_by_file.items():
        for line_num, _kp, _val, finding in items:
            rows.append((finding.display, finding.masked, path, line_num))
    return rows


def _rotation_items(found_by_file: dict) -> list[tuple[str, str]]:
    rules = sorted({
        finding.rule
        for items in found_by_file.values()
        for _, _, _, finding in items
    })
    return [
        (rule, ROTATION_GUIDANCE.get(rule, "rotate via the issuing provider"))
        for rule in rules
    ]


def _json_payload(found_by_file: dict, source: Source) -> list[dict]:
    payload = []
    for path, items in found_by_file.items():
        relpath = ui.rel(path, source.root)
        for line_num, keypath, _val, finding in items:
            payload.append({
                "fingerprint": ignore_mod.fingerprint(relpath, line_num, finding.rule),
                "file": str(path),
                "line": line_num,
                "keypath": keypath,
                "rule": finding.rule,
                "display": finding.display,
                "masked": finding.masked,
            })
    return payload


def _output_json(found_by_file: dict, source: Source, output: Path | None,
                 suppressed: int) -> int:
    """Emit JSON. With -o (or a flood-risk tty) write to a file and keep
    stdout/scrollback clean; otherwise print to stdout for piping."""
    payload = _json_payload(found_by_file, source)
    code = 0 if not payload else 1

    if output is not None:
        _write_text(output, json.dumps(payload, indent=2) + "\n")
        print(f"{len(payload)} finding(s) written to {output}", file=sys.stderr)
        return code

    flood = (len(payload) > JSON_FLOOD_LIMIT
             and getattr(sys.stdout, "isatty", lambda: False)())
    if flood:
        target = Path.cwd() / DEFAULT_JSON_NAME
        _write_text(target, json.dumps(payload, indent=2) + "\n")
        print(f"{len(payload)} findings — too many to print; written to "
              f"{target}\n  view with:  cat {DEFAULT_JSON_NAME} | "
              f"python -m json.tool   (or open it)", file=sys.stderr)
        return code

    print(json.dumps(payload, indent=2))
    if suppressed:
        print(f"({suppressed} suppressed by .agentsweepignore)", file=sys.stderr)
    return code


def _show_findings(found_by_file: dict, source: Source,
                   output: Path | None) -> None:
    """Human findings table — capped on a real terminal so a huge scan can't
    bury the screen; the full set always goes to a report file in that case
    (or to -o if given)."""
    rows = _table_rows(found_by_file)
    on_tty = ui.console.is_terminal
    capped = on_tty and len(rows) > MAX_TABLE_ROWS

    if output is not None:
        _write_text(output, json.dumps(_json_payload(found_by_file, source),
                                       indent=2) + "\n")

    if capped:
        ui.findings_table(rows[:MAX_TABLE_ROWS], source.root)
        report = output if output is not None else Path.cwd() / DEFAULT_REPORT_NAME
        if output is None:
            _write_text(report, _text_report(found_by_file, source))
        ui.warn_line(f"…and {len(rows) - MAX_TABLE_ROWS} more — full list "
                     f"written to {report}")
    else:
        ui.findings_table(rows, source.root)
        if output is not None:
            ui.warn_line(f"{len(rows)} finding(s) also written to {output}")


def _text_report(found_by_file: dict, source: Source) -> str:
    lines = ["agentsweep findings report", ""]
    for item in _json_payload(found_by_file, source):
        lines.append(f"{item['fingerprint']}")
        lines.append(f"    {item['display']}  {item['masked']}")
    lines.append("")
    lines.append("Rotate these — see the provider URLs printed by the scan.")
    return "\n".join(lines) + "\n"


def _write_text(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as e:
        print(f"Could not write {path}: {e}", file=sys.stderr)


# Backup patterns undo restores: JSONL transcripts, whole-file JSON and
# markdown histories, plus the SQLite stores (Cursor/Windsurf *.vscdb,
# OpenCode opencode.db, Hermes/Goose *.db).
_BACKUP_GLOBS = ("*.jsonl.bak", "*.json.bak", "*.md.bak",
                 "*.vscdb.bak", "*.db.bak")


def undo(args) -> int:
    """Restore agentsweep .bak backups over their redacted files.

    Scriptable: prompts for confirmation only on an interactive terminal.
    Exit 0 on success or nothing-to-do, 2 if any restore failed.
    """
    source_cls = SOURCES[args.source]
    source: Source = source_cls(root=args.root) if args.root else source_cls()
    roots = [r for r in source.roots() if r.exists()]
    if not roots:
        print(f"No history root at {source.root}", file=sys.stderr)
        return 0
    backups = sorted({p for root in roots
                      for pat in _BACKUP_GLOBS
                      for p in root.rglob(pat)})
    if not backups:
        print(f"No .bak backups found under {source.root}", file=sys.stderr)
        return 0

    interactive = (sys.stdin.isatty() and ui.console.is_terminal
                   if hasattr(sys.stdin, "isatty") else False)
    if interactive:
        print(f"  {len(backups)} backup(s) found under {source.root}")
        try:
            if input("  restore them over the redacted files? [y/N]: "
                     ).strip().lower() != "y":
                ui.warn_line("cancelled — backups kept as-is")
                return 0
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

    errors = 0
    for bak in backups:
        original = bak.with_name(bak.name[: -len(".bak")])
        try:
            import os
            os.replace(bak, original)
            ui.redact_row("ok", ui.rel(original, source.root), "restored from .bak")
        except OSError as e:
            ui.redact_row("fail", ui.rel(bak, source.root), str(e))
            errors += 1
    return 0 if errors == 0 else 2


def purge(args) -> int:
    """Delete agentsweep .bak backups once the leaked keys are rotated.

    The backups hold the pre-redaction originals — plaintext secrets — so
    a sweep isn't finished until they're gone. Deleting them is permanent
    (``undo`` stops working for those files), so this prompts on a
    terminal and refuses without ``--yes`` everywhere else.

    Exit codes: 0 on success, nothing-to-do, or an interactive ``n``
    (backups kept — a no-op, matching ``undo``); 2 when non-interactive
    without ``--yes`` (refused to act blind) or if any delete failed.
    """
    source_cls = SOURCES[args.source]
    source: Source = source_cls(root=args.root) if args.root else source_cls()
    roots = [r for r in source.roots() if r.exists()]
    if not roots:
        print(f"No history root at {source.root}", file=sys.stderr)
        return 0
    backups = sorted({p for root in roots
                      for pat in _BACKUP_GLOBS
                      for p in root.rglob(pat)})
    if not backups:
        print(f"No .bak backups found under {source.root}", file=sys.stderr)
        return 0

    if not getattr(args, "yes", False):
        interactive = (sys.stdin.isatty() and ui.console.is_terminal
                       if hasattr(sys.stdin, "isatty") else False)
        if not interactive:
            print("purge permanently deletes the pre-redaction originals; "
                  "re-run with --yes to confirm.", file=sys.stderr)
            return 2
        print(f"  {len(backups)} backup(s) found under {source.root}")
        print("  they hold the PRE-redaction originals — deleting them is "
              "permanent and `undo` will no longer work")
        try:
            if input("  delete them permanently? [y/N]: "
                     ).strip().lower() != "y":
                ui.warn_line("cancelled — backups kept as-is")
                return 0
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

    errors = 0
    for bak in backups:
        try:
            bak.unlink()
            ui.redact_row("ok", ui.rel(bak, source.root), "backup deleted")
        except OSError as e:
            ui.redact_row("fail", ui.rel(bak, source.root), str(e))
            errors += 1
    return 0 if errors == 0 else 2


def _redact_all(
    source: Source,
    found_by_file: dict,
    backup: bool,
    force: bool,
) -> tuple[list[tuple[str, str, str]], int]:
    """Apply redactions, returning ((status, path_display, note) rows, error count).

    Rows are collected rather than printed so the REDACT stage line can
    report the real outcome (ok/partial/all-failed) above them.
    """
    rows: list[tuple[str, str, str]] = []
    errors = 0
    for path, items in found_by_file.items():
        display = ui.rel(path, source.root)
        try:
            safety_check(path, source.roots(), force=force)
        except SafetyError as e:
            rows.append(("skip", display, str(e)))
            errors += 1
            continue

        redactions = _build_redactions(items)
        try:
            new_content = source.apply_redactions(path, redactions)
            record = safe_write(path, new_content, backup=backup,
                                fmt=source.content_format(path))
            note = f".bak: {record.backup.name}" if record.backup else "no backup"
            rows.append(("ok", display, note))
        except SafetyError as e:
            rows.append(("fail", display, str(e)))
            errors += 1
        except Exception as e:
            rows.append(("fail", display, f"{type(e).__name__}: {e}"))
            errors += 1
    return rows, errors


def _preflight_gates(source: Source, source_cls: type[Source], args) -> int | None:
    """Return an exit code if a gate blocks --fix; otherwise None to continue."""
    if is_production_root(source, source_cls) and not args.allow_production:
        ui.stage(4, "fail", "REDACT", "blocked by safety gate")
        ui.gate_panel("alpha safety gate", [
            "Refusing to --fix the default production root:",
            f"  {source.root}",
            "",
            "agentsweep is in alpha. To proceed, either:",
            "  1. copy history elsewhere and pass --root <that path>, OR",
            "  2. re-run with --allow-production (explicit opt-in).",
        ])
        return 2

    running, marker = is_agent_running(source.process_markers)
    if running and not args.force:
        ui.stage(4, "fail", "REDACT", "blocked by safety gate")
        ui.gate_panel("active session gate", [
            f"{source.display_name} appears to be running (marker: {marker!r}).",
            f"Close all {source.display_name} sessions before --fix,",
            "or pass --force to proceed anyway.",
        ])
        return 2
    if running and args.force:
        ui.warn_line(
            f"--force: proceeding while {source.display_name} appears to be "
            f"running (marker: {marker!r})"
        )

    return None


def _build_redactions(items: list[tuple[int, list, str, Finding]]) -> list[tuple[int, list, str]]:
    # Group findings by the (line, keypath) pair so multiple secrets inside one
    # string are applied in a single rewrite.
    by_loc: dict[tuple[int, tuple], tuple[str, list[Finding]]] = {}
    for line_num, kp, val, finding in items:
        key = (line_num, tuple(kp))
        if key not in by_loc:
            by_loc[key] = (val, [])
        by_loc[key][1].append(finding)

    redactions: list[tuple[int, list, str]] = []
    for (line_num, kp_tuple), (original, findings) in by_loc.items():
        new_val = original
        # Replace right-to-left so earlier spans' offsets stay valid.
        for fd in sorted(findings, key=lambda x: x.span[0], reverse=True):
            start, end = fd.span
            new_val = new_val[:start] + REDACT_TEMPLATE.format(rule=fd.rule) + new_val[end:]
        redactions.append((line_num, list(kp_tuple), new_val))
    return redactions
