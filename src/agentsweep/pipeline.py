"""The 5-stage scan/redact pipeline: DISCOVER → SCAN → FINDINGS → REDACT → ROTATE.

Owns all run orchestration and the --json/exit-code contracts. cli.py
parses flags and hands the parsed namespace to run(); ui owns rendering.
"""
from __future__ import annotations

import difflib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import __version__, ui
from . import ignore as ignore_mod
from .preflight import is_agent_running, is_production_root
from .redactor import SafetyError, safe_write, safety_check
from .scanner import ROTATION_GUIDANCE, RULES, Finding, scan_text
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


def run(args, *, _findings_out: list | None = None,
        _force_recoverable_out: list | None = None) -> int:
    """Execute one scan (and optional redact) run. Exit codes:
    0 clean · 1 findings (scan-only) · 2 gate-blocked, write error, or bad path.

    When _findings_out is provided and args.fix is False, appends
    (source, found_by_file) to it so the caller can pass pre-computed
    findings to offer_redaction(), avoiding a double-scan on REDACT.
    """
    source_cls = SOURCES[args.source]
    source: Source = source_cls(root=args.root) if args.root else source_cls()
    output: Path | None = _opt(args, "output")

    as_sarif = _opt(args, "format") == "sarif"
    # Both machine formats share every no-banner/no-styling branch below; they
    # differ only in what an empty result set looks like on stdout.
    machine = bool(args.json) or as_sarif

    def _print_empty_machine_output() -> None:
        # stdout must stay parseable in every machine-format run, including
        # user errors — for SARIF that means a valid document, not "[]".
        if as_sarif:
            print(json.dumps(_sarif_document([]), indent=2))
        elif args.json:
            print("[]")

    if args.root is not None and not source.root.exists():
        print(f"Path not found: {source.root}", file=sys.stderr)
        for hint in _suggest_paths(source.root):
            print(f"  did you mean: {source.root.parent / hint}", file=sys.stderr)
        if machine:
            _print_empty_machine_output()
        return 2

    if not machine:
        ui.banner(__version__)
        if getattr(source, "experimental", False):
            ui.warn_line(
                f"{source.display_name} is an experimental source — its history "
                f"path/format is inferred from research and not yet verified "
                f"against a real install, so it may find nothing")

    if not machine:
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
        if machine:
            _print_empty_machine_output()
        else:
            ui.stage(1, "warn", "DISCOVER", source.name,
                     f"no history files under {source.root}", err=True)
        return 0

    ignores = (ignore_mod.IgnoreSet() if _opt(args, "no_ignore")
               else ignore_mod.load([source.root, Path.cwd()]))

    if machine:
        found_by_file, _, suppressed, truncated = _scan(source, files, ignores)
        if truncated:
            print(f"warning: {len(truncated)} file(s) exceeded the scan budget "
                  f"and were truncated", file=sys.stderr)
        if as_sarif:
            return _emit_sarif(_json_payload(found_by_file, source),
                               output, suppressed)
        return _output_json(found_by_file, source, output, suppressed)

    ui.stage(1, "ok", "DISCOVER", source.name, f"{len(files)} file(s)", source.root)

    t0 = time.perf_counter()
    with ui.scan_progress(len(files)) as progress:
        found_by_file, strings_scanned, suppressed, truncated = _scan(
            source, files, ignores, progress)
    elapsed = time.perf_counter() - t0

    ui.stage(2, "ok", "SCAN", f"{len(files)} file(s)",
             f"{strings_scanned} string(s)", f"{elapsed:.1f}s")
    if truncated:
        ui.warn_line(f"{len(truncated)} file(s) exceeded the "
                     f"{_MAX_FILE_SCAN_CHARS // 1_000_000}MB scan budget and were "
                     f"truncated (likely cache blobs, not conversation text)")

    if suppressed:
        ui.warn_line(f"{suppressed} finding(s) suppressed by .agentsweepignore")

    if not found_by_file:
        ui.stage(3, "ok", "FINDINGS", "no secrets found")
        ui.stage(4, "skip", "REDACT", "nothing to redact")
        ui.stage(5, "skip", "ROTATE", "nothing to rotate")
        ui.contribute_line()
        return 0

    total = sum(len(v) for v in found_by_file.values())
    ui.stage(3, "fail", "FINDINGS", f"{total} secret(s) in {len(found_by_file)} file(s)")
    _show_findings(found_by_file, source, output)

    if not args.fix:
        ui.stage(4, "skip", "REDACT",
                 "skipped — run with --fix to redact in place (.bak backups)")
        ui.stage(5, "warn", "ROTATE", "these keys are still live")
        ui.rotation_panel(_rotation_items(found_by_file))
        ui.contribute_line()
        if _findings_out is not None:
            _findings_out.append((source, found_by_file))
        return 1

    gate_err, gate_recoverable = _preflight_gates(source, source_cls, args)
    if gate_err is not None:
        # The user who most needs rotation guidance is the one we just
        # refused to redact for — the keys are confirmed live.
        ui.stage(5, "warn", "ROTATE", "these keys are still live")
        ui.rotation_panel(_rotation_items(found_by_file))
        if _force_recoverable_out is not None:
            _force_recoverable_out.append(gate_recoverable)
        return gate_err

    rows, errors, recoverable = _redact_all(
        source=source,
        found_by_file=found_by_file,
        backup=not args.no_backup,
        force=args.force,
    )
    if _force_recoverable_out is not None:
        _force_recoverable_out.append(recoverable)
    return _render_redact_result(rows, errors, found_by_file)


def _render_redact_result(rows, errors: int, found_by_file: dict) -> int:
    """Render the REDACT + ROTATE stage lines and rows for a redaction run.

    Shared by run() and redact_findings() so the two never drift. Returns the
    exit code: 0 if every write succeeded, else 2.
    """
    ok_count = sum(1 for status, _, _ in rows if status == "ok")
    already = sum(1 for status, _, note in rows
                  if status == "skip" and "already redacted" in note)
    redacted = ok_count + already  # this pass plus any prior pass
    if errors == 0 and ok_count:
        ui.stage(4, "ok", "REDACT", f"{ok_count}/{len(rows)} file(s) rewritten")
    elif errors == 0 and already:
        ui.stage(4, "ok", "REDACT", f"{already} file(s) already redacted")
    elif ok_count:
        ui.stage(4, "warn", "REDACT", f"{ok_count}/{len(rows)} file(s) rewritten")
    else:
        ui.stage(4, "fail", "REDACT", f"0/{len(rows)} file(s) rewritten")
    for status, path_display, note in rows:
        ui.redact_row(status, path_display, note)

    if redacted:
        ui.stage(5, "warn", "ROTATE", "redacted locally", "keys live until rotated")
    else:
        ui.stage(5, "warn", "ROTATE", "nothing redacted", "these keys are still live")
    ui.rotation_panel(_rotation_items(found_by_file))
    return 0 if errors == 0 else 2


def redact_findings(args, source: Source, found_by_file: dict, *,
                    _force_recoverable_out: list | None = None) -> int:
    """Apply REDACT + ROTATE using pre-computed findings; skip DISCOVER + SCAN.

    Called from offer_redaction() when the first scan cached its results via
    _findings_out, so the user never sees the pipeline restart from scratch.
    Exit codes: 0 clean, 2 gate-blocked or write error.
    """
    source_cls = SOURCES[args.source]
    gate_err, gate_recoverable = _preflight_gates(source, source_cls, args)
    if gate_err is not None:
        ui.stage(5, "warn", "ROTATE", "these keys are still live")
        ui.rotation_panel(_rotation_items(found_by_file))
        if _force_recoverable_out is not None:
            _force_recoverable_out.append(gate_recoverable)
        return gate_err

    rows, errors, recoverable = _redact_all(
        source=source,
        found_by_file=found_by_file,
        backup=not args.no_backup,
        force=args.force,
    )
    if _force_recoverable_out is not None:
        _force_recoverable_out.append(recoverable)
    return _render_redact_result(rows, errors, found_by_file)


def _source_rows() -> list[dict]:
    """Describe every registered source: key, name, default root, detection.

    ``detected`` comes from ``Source.is_detected()`` (default: history root
    exists). Most sources stay O(1). Aider overrides this because its root is
    the home directory, which always exists.
    """
    rows: list[dict] = []
    for key, cls in SOURCES.items():
        try:
            src = cls()
            root = src.root
            detected = src.is_detected()
        except Exception:
            root, detected = None, False
        rows.append({
            "source": key,
            "display": getattr(cls, "display_name", key),
            "experimental": bool(getattr(cls, "experimental", False)),
            "root": str(root) if root is not None else "",
            "detected": detected,
        })
    return rows


def list_sources(args) -> int:
    """List every supported agent source and whether its history root exists.

    Read-only and side-effect free — reads no history, writes nothing. Always
    exits 0. With ``--detected`` only sources found on this machine are shown;
    with ``--json`` the list is emitted as machine-readable JSON to stdout.
    """
    rows = _source_rows()
    if getattr(args, "detected", False):
        rows = [r for r in rows if r["detected"]]

    if getattr(args, "json", False):
        print(json.dumps(rows, indent=2))
        return 0

    ui.banner(__version__)
    if not rows:
        ui.warn_line("no agent history found on this machine")
        return 0
    ui.sources_table(rows)
    return 0


def run_all(args) -> int:
    """Scan every registered (or detected) source and aggregate findings.

    Scan-only — redaction stays per-source via ``fix --source <name>``.

    Exit codes: 0 clean / nothing scanned · 1 findings · 2 misuse (e.g. fix).
    Missing roots are skipped (not errors), matching single-source "no files
    under root → 0". ``--detected`` restricts to sources that report history
    on this machine (same signal as ``list-sources --detected``).
    """
    if _opt(args, "fix", False):
        print(
            "fix --all is not supported; "
            "run: agentsweep fix --source <name>",
            file=sys.stderr,
        )
        return 2

    output: Path | None = _opt(args, "output")
    as_sarif = _opt(args, "format") == "sarif"
    as_json = bool(_opt(args, "json", False)) or as_sarif
    detected_only = bool(_opt(args, "detected", False))
    no_ignore = bool(_opt(args, "no_ignore", False))

    selected: list[tuple[str, Source]] = []
    experimental: list[str] = []
    for key, cls in SOURCES.items():
        try:
            src = cls()
        except Exception:
            continue
        if detected_only and not src.is_detected():
            continue
        selected.append((key, src))
        if getattr(src, "experimental", False):
            experimental.append(getattr(src, "display_name", key))

    if not selected:
        msg = ("no agent history roots found on this machine"
               if detected_only else "no sources available to scan")
        print(msg, file=sys.stderr)
        if as_json:
            print("[]")
        else:
            ui.banner(__version__)
            ui.warn_line(msg)
        return 0

    if not as_json:
        ui.banner(__version__)
        if experimental:
            ui.warn_line(
                f"includes experimental source(s): {', '.join(experimental)} "
                f"— history path/format not yet verified against a real install"
            )

    # Phase 1: discover files per source (stream status so large roots
    # don't look hung — same contract as single-source run()).
    discovered: list[tuple[str, Source, list[Path]]] = []
    if as_json:
        for key, source in selected:
            try:
                files = list(source.iter_files())
            except Exception:
                files = []
            if files:
                discovered.append((key, source, files))
    else:
        with ui.console.status("") as status:
            for key, source in selected:
                try:
                    files: list[Path] = []
                    for f in source.iter_files():
                        files.append(f)
                        status.update(
                            f"[dim]Discovering[/] [bold]{key}[/bold]"
                            f" … [yellow]{len(files):,}[/] file(s)"
                        )
                except Exception:
                    files = []
                if files:
                    discovered.append((key, source, files))

    total_files = sum(len(f) for _, _, f in discovered)

    if total_files == 0:
        print("No history files found under any selected source", file=sys.stderr)
        if as_json:
            print("[]")
        else:
            ui.stage(1, "warn", "DISCOVER", f"{len(selected)} source(s)",
                     "no history files", err=True)
            ui.stage(2, "skip", "SCAN", "nothing to scan")
            ui.stage(3, "ok", "FINDINGS", "no secrets found")
            ui.stage(4, "skip", "REDACT", "nothing to redact")
            ui.stage(5, "skip", "ROTATE", "nothing to rotate")
            ui.contribute_line()
        return 0

    if not as_json:
        ui.stage(1, "ok", "DISCOVER", f"{len(discovered)} source(s)",
                 f"{total_files} file(s)")

    # Phase 2: scan sources sequentially; one shared progress bar over all
    # files (inner _scan still parallelizes within a source).
    per_source: list[tuple[str, Source, list[Path], dict, int, int, list[Path]]] = []
    total_strings = 0
    total_suppressed = 0
    total_truncated: list[Path] = []

    t0 = time.perf_counter()
    if as_json:
        for key, source, files in discovered:
            ignores = (ignore_mod.IgnoreSet() if no_ignore
                       else ignore_mod.load([source.root, Path.cwd()]))
            found_by_file, strings_scanned, suppressed, truncated = _scan(
                source, files, ignores)
            per_source.append(
                (key, source, files, found_by_file, strings_scanned,
                 suppressed, truncated)
            )
            total_strings += strings_scanned
            total_suppressed += suppressed
            total_truncated.extend(truncated)
    else:
        with ui.scan_progress(total_files) as progress:
            for key, source, files in discovered:
                ignores = (ignore_mod.IgnoreSet() if no_ignore
                           else ignore_mod.load([source.root, Path.cwd()]))
                found_by_file, strings_scanned, suppressed, truncated = _scan(
                    source, files, ignores, progress)
                per_source.append(
                    (key, source, files, found_by_file, strings_scanned,
                     suppressed, truncated)
                )
                total_strings += strings_scanned
                total_suppressed += suppressed
                total_truncated.extend(truncated)
    elapsed = time.perf_counter() - t0

    if as_json:
        payload: list[dict] = []
        for _key, source, _files, found_by_file, _sc, _sup, _tr in per_source:
            payload.extend(_json_payload(found_by_file, source))
        # Match single-source run(): scan-budget cap is reported, never silent.
        if total_truncated:
            print(
                f"warning: {len(total_truncated)} file(s) exceeded the scan budget "
                f"and were truncated",
                file=sys.stderr,
            )
        if as_sarif:
            return _emit_sarif(payload, output, total_suppressed)
        return _emit_json_payload(payload, output, total_suppressed)

    ui.stage(2, "ok", "SCAN", f"{total_files} file(s)",
             f"{total_strings} string(s)", f"{elapsed:.1f}s")
    if total_truncated:
        ui.warn_line(
            f"{len(total_truncated)} file(s) exceeded the "
            f"{_MAX_FILE_SCAN_CHARS // 1_000_000}MB scan budget and were truncated"
        )
    if total_suppressed:
        ui.warn_line(
            f"{total_suppressed} finding(s) suppressed by .agentsweepignore"
        )

    dirty = [(k, s, fbf) for k, s, _files, fbf, _sc, _sup, _tr in per_source if fbf]
    if not dirty:
        ui.stage(3, "ok", "FINDINGS", "no secrets found")
        ui.stage(4, "skip", "REDACT", "nothing to redact")
        ui.stage(5, "skip", "ROTATE", "nothing to rotate")
        ui.contribute_line()
        return 0

    grand = sum(len(items) for _k, _s, fbf in dirty for items in fbf.values())
    ui.stage(3, "fail", "FINDINGS",
             f"{grand} secret(s) across {len(dirty)} source(s)")

    # Display tables per source without writing the fixed overflow report
    # path (that would clobber across sources). One aggregated report after.
    combined_payload: list[dict] = []
    any_source_capped = False
    rows_shown = 0
    on_tty = ui.console.is_terminal
    for key, source, fbf in dirty:
        src_total = sum(len(v) for v in fbf.values())
        ui.warn_line(f"{key}: {src_total} secret(s) under {source.root}")
        rows = _table_rows(fbf)
        remaining_budget = max(0, MAX_TABLE_ROWS - rows_shown) if on_tty else len(rows)
        if on_tty and (len(rows) > remaining_budget or remaining_budget == 0):
            any_source_capped = True
            if remaining_budget > 0:
                ui.findings_table(rows[:remaining_budget], source.root)
                rows_shown += remaining_budget
                ui.warn_line(
                    f"{key}: …and {len(rows) - remaining_budget} more "
                    f"(full multi-source list written after all sources)"
                )
            else:
                ui.warn_line(
                    f"{key}: {src_total} secret(s) omitted from table "
                    f"(global cap {MAX_TABLE_ROWS}; see full report)"
                )
        else:
            ui.findings_table(rows, source.root)
            rows_shown += len(rows)
        combined_payload.extend(_json_payload(fbf, source))

    # Single overflow destination: -o JSON if given, else one text report
    # that includes every source (never per-source clobber of DEFAULT_REPORT).
    needs_overflow = on_tty and (any_source_capped or grand > MAX_TABLE_ROWS)
    if output is not None:
        _write_text(output, json.dumps(combined_payload, indent=2) + "\n")
        ui.warn_line(f"{len(combined_payload)} finding(s) also written to {output}")
    elif needs_overflow:
        report = Path.cwd() / DEFAULT_REPORT_NAME
        _write_text(report, _text_report_multi(combined_payload))
        ui.warn_line(
            f"full multi-source findings ({grand}) written to {report}"
        )

    dirty_names = ", ".join(k for k, _s, _f in dirty)
    ui.stage(4, "skip", "REDACT",
             f"skipped — run: agentsweep fix --source <name>  "
             f"(dirty: {dirty_names})")
    ui.stage(5, "warn", "ROTATE", "these keys are still live")
    # Flatten across sources — do not merge by Path (collisions across roots).
    ui.rotation_panel(_rotation_items_multi(dirty))
    ui.contribute_line()
    return 1


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


# A single history file rarely holds more than a few MB of actual conversation
# text. Some stores (e.g. a Cursor state.vscdb stuffed with cache JSON) can
# instead explode into tens of millions of tiny leaf strings — gigabytes of
# content — which would stall the scan for minutes and, on a worker thread,
# block Ctrl-C. Stop scanning a file once its text crosses this budget and flag
# it as truncated so the cap is reported, never silent.
_MAX_FILE_SCAN_CHARS = 50_000_000


def _scan_file(
    source: Source,
    f: Path,
    ignores,
) -> tuple[Path, list[tuple[int, list, str, Finding]], int, int, bool]:
    """Scan a single file; safe to call from a thread pool worker.

    Returns (path, findings_list, strings_scanned, suppressed_count, truncated).
    `truncated` is True when the per-file scan budget was hit and the rest of
    the file was skipped. Callbacks are NOT invoked here — the caller dispatches
    them on the main thread after each future completes, so Rich Live is never
    touched from a worker thread.
    """
    items: list[tuple[int, list, str, Finding]] = []
    strings_scanned = 0
    suppressed = 0
    scanned_chars = 0
    truncated = False
    relpath = ui.rel(f, source.root)
    for line_num, keypath, value in source.iter_strings(f):
        strings_scanned += 1
        scanned_chars += len(value)
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
        if scanned_chars > _MAX_FILE_SCAN_CHARS:
            truncated = True
            break
    return f, items, strings_scanned, suppressed, truncated


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
) -> tuple[dict[Path, list[tuple[int, list, str, Finding]]], int, int, list[Path]]:
    out: dict[Path, list[tuple[int, list, str, Finding]]] = {}
    strings_scanned = 0
    suppressed = 0
    truncated: list[Path] = []

    # For tiny workloads the thread-pool overhead exceeds the I/O overlap
    # benefit; fall back to the sequential path for ≤4 files.
    if len(files) <= 4:
        for f in files:
            if on_file is not None:
                on_file(f)
            _, items, sc, sup, trunc = _scan_file(source, f, ignores)
            strings_scanned += sc
            suppressed += sup
            if trunc:
                truncated.append(f)
            for entry in items:
                out.setdefault(f, []).append(entry)
                if on_finding is not None:
                    on_finding(entry[3])
        return out, strings_scanned, suppressed, truncated

    workers = min(_SCAN_WORKERS, len(files))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_scan_file, source, f, ignores): f
            for f in files
        }
        for fut in as_completed(futures):
            f, items, sc, sup, trunc = fut.result()
            strings_scanned += sc
            suppressed += sup
            if trunc:
                truncated.append(f)
            if on_file is not None:
                on_file(f)
            for entry in items:
                out.setdefault(f, []).append(entry)
                if on_finding is not None:
                    on_finding(entry[3])
    return out, strings_scanned, suppressed, truncated


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


def _rotation_items_multi(
    dirty: list[tuple[str, Source, dict]],
) -> list[tuple[str, str]]:
    """Union of rotation guidance across sources (Path-merge-safe)."""
    rules = sorted({
        finding.rule
        for _key, _source, fbf in dirty
        for items in fbf.values()
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
                "source": source.name,
                "fingerprint": ignore_mod.fingerprint(relpath, line_num, finding.rule),
                "file": str(path),
                "line": line_num,
                "keypath": keypath,
                "rule": finding.rule,
                "display": finding.display,
                "masked": finding.masked,
            })
    return payload


SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
_PROJECT_URL = "https://github.com/Ishannaik/agent-sweep"


def _sarif_document(payload: list[dict]) -> dict:
    """Build a SARIF 2.1.0 document from the JSON findings payload.

    Only rules that actually matched become tool.driver.rules, so a run
    carries guidance for what was found rather than all of RULES. Message
    text reuses each finding's `masked` preview; the plaintext secret is
    never read here, so it cannot reach the report.
    """
    displays = {rule: display for rule, display, _pattern in RULES}

    rule_ids: list[str] = []
    for f in payload:
        if f["rule"] not in rule_ids:
            rule_ids.append(f["rule"])

    rules: list[dict] = []
    for rule_id in rule_ids:
        descriptor: dict = {
            "id": rule_id,
            "name": displays.get(rule_id, rule_id),
            "shortDescription": {"text": displays.get(rule_id, rule_id)},
        }
        guidance = ROTATION_GUIDANCE.get(rule_id)
        if guidance:
            descriptor["help"] = {"text": guidance}
        rules.append(descriptor)

    index_of = {rule_id: i for i, rule_id in enumerate(rule_ids)}
    results: list[dict] = []
    for f in payload:
        results.append({
            "ruleId": f["rule"],
            "ruleIndex": index_of[f["rule"]],
            "level": "error",
            "message": {
                "text": (f"{f['display']} found in {f['source']} history: "
                         f"{f['masked']}"),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": Path(f["file"]).resolve().as_uri(),
                    },
                    "region": {"startLine": max(1, int(f["line"]))},
                },
            }],
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "agentsweep",
                "version": __version__,
                "informationUri": _PROJECT_URL,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def _emit_sarif(payload: list[dict], output: Path | None,
                suppressed: int) -> int:
    """Emit a SARIF report to `output` or stdout.

    Machine-clean like the JSON path — no banner, no styling — and the exit
    code matches it: 1 with findings, 0 clean.
    """
    code = 0 if not payload else 1
    text = json.dumps(_sarif_document(payload), indent=2) + "\n"

    if output is not None:
        _write_text(output, text)
        print(f"{len(payload)} finding(s) written to {output}", file=sys.stderr)
        return code

    print(text, end="")
    if suppressed:
        print(f"({suppressed} suppressed by .agentsweepignore)", file=sys.stderr)
    return code


def _emit_json_payload(payload: list[dict], output: Path | None,
                       suppressed: int) -> int:
    """Shared JSON emission for single- and multi-source scans."""
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


def _output_json(found_by_file: dict, source: Source, output: Path | None,
                 suppressed: int) -> int:
    """Emit JSON. With -o (or a flood-risk tty) write to a file and keep
    stdout/scrollback clean; otherwise print to stdout for piping."""
    return _emit_json_payload(_json_payload(found_by_file, source),
                              output, suppressed)


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


def _text_report_multi(payload: list[dict]) -> str:
    """Aggregated human report for scan --all (includes source on every row)."""
    lines = ["agentsweep findings report (all sources)", ""]
    for item in payload:
        src = item.get("source", "?")
        lines.append(f"[{src}] {item['fingerprint']}")
        lines.append(f"    {item['display']}  {item['masked']}")
    lines.append("")
    lines.append("Rotate these — see the provider URLs printed by the scan.")
    lines.append("Redact per source: agentsweep fix --source <name>")
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
                 "*.vscdb.bak", "*.db.bak",
                 # SQLite WAL sidecars, retired with their database by
                 # safe_write. undo restores them; purge deletes them.
                 "*.db-wal.bak", "*.db-shm.bak",
                 "*.vscdb-wal.bak", "*.vscdb-shm.bak",
                 "*.sqlite.bak", "*.sqlite-wal.bak", "*.sqlite-shm.bak")


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
) -> tuple[list[tuple[str, str, str]], int, bool]:
    """Apply redactions, returning (rows, error_count, force_recoverable).

    Rows are (status, path_display, note); status is "ok", "skip" or "fail".
    A file whose .bak already exists was redacted in a prior pass, so it is a
    "skip" ("already redacted"), NOT an error. `force_recoverable` is True if
    any failure was an active-session gate (mtime) that --force could bypass —
    the caller uses it to decide whether offering --force is worthwhile.
    """
    rows: list[tuple[str, str, str]] = []
    errors = 0
    recoverable = False
    for path, items in found_by_file.items():
        display = ui.rel(path, source.root)
        try:
            safety_check(path, source.roots(), force=force)
        except SafetyError as e:
            rows.append(("skip", display, str(e)))
            errors += 1
            recoverable = recoverable or e.force_recoverable
            continue

        redactions = _build_redactions(items)
        try:
            new_content = source.apply_redactions(path, redactions)
            record = safe_write(path, new_content, backup=backup,
                                fmt=source.content_format(path),
                                sidecars=source.sidecars(path))
            if record.unchanged:
                # File was already in the redacted state — calm skip, not a fail.
                rows.append(("skip", display, "already redacted (no change)"))
            else:
                note = (f".bak: {record.backup.name}" if record.backup
                        else "no backup")
                rows.append(("ok", display, note))
        except SafetyError as e:
            rows.append(("fail", display, str(e)))
            errors += 1
            recoverable = recoverable or e.force_recoverable
        except Exception as e:
            rows.append(("fail", display, f"{type(e).__name__}: {e}"))
            errors += 1
    return rows, errors, recoverable


def _preflight_gates(source: Source, source_cls: type[Source],
                     args) -> tuple[int | None, bool]:
    """Check the --fix gates. Returns (exit_code_or_None, force_recoverable).

    force_recoverable is True only when the block is the active-session
    (running-agent) gate that --force can bypass; the production-root gate is
    cleared by --allow-production, not --force, so it is not force-recoverable.
    """
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
        return 2, False

    running, marker = is_agent_running(source.process_markers)
    if running and not args.force:
        ui.stage(4, "fail", "REDACT", "blocked by safety gate")
        ui.gate_panel("active session gate", [
            f"{source.display_name} appears to be running (marker: {marker!r}).",
            f"Close all {source.display_name} sessions before --fix,",
            "or pass --force to proceed anyway.",
        ])
        return 2, True
    if running and args.force:
        ui.warn_line(
            f"--force: proceeding while {source.display_name} appears to be "
            f"running (marker: {marker!r})"
        )

    return None, False


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
