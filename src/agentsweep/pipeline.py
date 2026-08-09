"""The 5-stage scan/redact pipeline: DISCOVER → SCAN → FINDINGS → REDACT → ROTATE.

Owns all run orchestration and the --json/exit-code contracts. cli.py
parses flags and hands the parsed namespace to run(); ui owns rendering.
"""
from __future__ import annotations

from collections import Counter
import difflib
from typing import TypeAlias, cast
import json
import os
import sys
import threading
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

JsonObject: TypeAlias = dict[str, object]
JsonList: TypeAlias = list[JsonObject]
JsonPayload: TypeAlias = JsonList | JsonObject


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
    if as_sarif and getattr(args, "stats", False):
        print("error: --stats is not supported in SARIF mode; "
              "omit --stats or use --json instead", file=sys.stderr)
        return 2
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

    if args.root is not None and not source.root.is_dir():
        print(f"--root must be a directory, not a file: {source.root}", file=sys.stderr)
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
        stats_flag = getattr(args, "stats", False)
        if machine:
            if args.json and stats_flag:
                empty_stats = _stats_payload({}, source_key=source.name)
                _emit_json_payload(
                    {"findings": [], "stats": empty_stats}, output, 0)
            else:
                _print_empty_machine_output()
        else:
            ui.stage(1, "warn", "DISCOVER", source.name,
                     f"no history files under {source.root}", err=True)
            if stats_flag:
                _show_stats(_stats_payload({}, source_key=source.name))
        return 0

    ignores = (ignore_mod.IgnoreSet() if _opt(args, "no_ignore")
               else ignore_mod.load([source.root, Path.cwd()]))

    exclude_rules = set(_opt(args, "exclude_rule", set()))
    only_rules = _opt(args, "only_rule", None)
    only_rules = None if not only_rules else set(only_rules)

    if machine:
        found_by_file, _, suppressed, truncated = _scan(
            source,
            files,
            ignores,
            exclude_rules=exclude_rules,
            only_rules=only_rules,
        )
        if truncated:
            print(f"warning: {len(truncated)} file(s) exceeded the scan budget "
                  f"and were truncated", file=sys.stderr)
        _warn_leftover_backups(source, as_json=True)
        if as_sarif:
            return _emit_sarif(_json_payload(found_by_file, source),
                               output, suppressed)
        return _output_json(
            found_by_file,
            source,
            output,
            suppressed,
            report=getattr(args, "report", False),
            stats=getattr(args, "stats", False),
        )

    ui.stage(1, "ok", "DISCOVER", source.name, f"{len(files)} file(s)", source.root)

    t0 = time.perf_counter()
    with ui.scan_progress(len(files)) as progress:
        found_by_file, strings_scanned, suppressed, truncated = _scan(
            source,
            files,
            ignores,
            progress,
            exclude_rules=exclude_rules,
            only_rules=only_rules,
        )
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
        if getattr(args, "stats", False):
            empty_stats = _stats_payload(found_by_file, source_key=source.name)
            if output is not None:
                _write_text(output, json.dumps(
                    {"findings": [], "stats": empty_stats}, indent=2) + "\n")
                print(f"0 finding(s) written to {output}", file=sys.stderr)
            _show_stats(empty_stats)
        ui.stage(4, "skip", "REDACT", "nothing to redact")
        ui.stage(5, "skip", "ROTATE", "nothing to rotate")
        _warn_leftover_backups(source, as_json=False)
        ui.contribute_line()
        return 0

    total = sum(len(v) for v in found_by_file.values())
    ui.stage(3, "fail", "FINDINGS", f"{total} secret(s) in {len(found_by_file)} file(s)")
    stats_payload = (_stats_payload(found_by_file, source_key=source.name)
                     if getattr(args, "stats", False) else None)
    _show_findings(found_by_file, source, output, stats=stats_payload)
    if stats_payload is not None:
        _show_stats(stats_payload)

    if not args.fix:
        ui.stage(4, "skip", "REDACT",
                 "skipped — run with --fix to redact in place (.bak backups)")
        ui.stage(5, "warn", "ROTATE", "these keys are still live")
        ui.rotation_panel(_rotation_items(found_by_file))
        _warn_leftover_backups(source, as_json=False)
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
        template=_opt(args, "redact_with", None) or REDACT_TEMPLATE,
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
        template=_opt(args, "redact_with", None) or REDACT_TEMPLATE,
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

    With ``--fix``, each source with findings is then redacted through the
    single-source path — see _fix_all_sources.

    Exit codes: 0 clean / nothing scanned / everything redacted · 1 findings
    (scan-only) · 2 a source was gate-blocked or errored during --fix.
    Missing roots are skipped (not errors), matching single-source "no files
    under root → 0". ``--detected`` restricts to sources that report history
    on this machine (same signal as ``list-sources --detected``).
    """
    output: Path | None = _opt(args, "output")
    as_sarif = _opt(args, "format") == "sarif"
    if as_sarif and _opt(args, "stats", False):
        print("error: --stats is not supported in SARIF mode; "
              "omit --stats or use --json instead", file=sys.stderr)
        return 2
    as_json = bool(_opt(args, "json", False)) or as_sarif
    report = getattr(args, "report", False)
    detected_only = bool(_opt(args, "detected", False))
    no_ignore = bool(_opt(args, "no_ignore", False))
    exclude_rules = set(_opt(args, "exclude_rule", set()))
    only_rules = _opt(args, "only_rule", None)
    only_rules = None if not only_rules else set(only_rules)

    selected: list[tuple[str, Source]] = []
    experimental: list[str] = []
    for key, cls in SOURCES.items():
        try:
            src = cls()
        except Exception:  # nosec B112 # skip a source whose constructor fails (e.g. unresolvable home dir) rather than aborting scan --all for every other source
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
        stats_flag = _opt(args, "stats", False)
        if as_json:
            if stats_flag:
                _emit_json_payload(
                    {"findings": [], "stats": _stats_payload_multi([])},
                    output, 0)
            else:
                print("[]")
        else:
            ui.banner(__version__)
            ui.warn_line(msg)
            if stats_flag:
                _show_stats(_stats_payload_multi([]))
        return 0

    if not as_json:
        ui.banner(__version__)
        if experimental:
            ui.warn_line(
                f"includes experimental source(s): {', '.join(experimental)} "
                f"— history path/format not yet verified against a real install"
            )

    # Phase 1: discover files for all sources concurrently.  Each source
    # walks its own independent root directory so there is no shared state
    # between workers.  Results are collected into a list keyed by the
    # original index so the final ordering matches `selected` regardless of
    # which worker finishes first.
    #
    # Discovery workers are capped at _SOURCE_WORKERS_CAP to ensure bounded
    # concurrency across the entire pipeline.
    _SOURCE_WORKERS_CAP = 4

    def _discover_one(key: str, source: Source) -> tuple[str, Source, list[Path]]:
        """Collect every file for a single source; safe to call from a thread."""
        try:
            files = list(source.iter_files())
        except Exception:
            files = []
        return key, source, files

    discover_workers = min(_SOURCE_WORKERS_CAP, max(1, len(selected)))
    discovered_by_index: dict[int, tuple[str, Source, list[Path]]] = {}

    if as_json:
        with ThreadPoolExecutor(max_workers=discover_workers) as disc_pool:
            disc_futures = {
                disc_pool.submit(_discover_one, key, source): idx
                for idx, (key, source) in enumerate(selected)
            }
            for fut in as_completed(disc_futures):
                idx = disc_futures[fut]
                key, source, files = fut.result()
                if files:
                    discovered_by_index[idx] = (key, source, files)
    else:
        completed_count = 0
        completed_lock = threading.Lock()

        def _discover_with_status(
            key: str, source: Source
        ) -> tuple[str, Source, list[Path]]:
            result = _discover_one(key, source)
            nonlocal completed_count
            with completed_lock:
                completed_count += 1

            return result

        with ui.console.status("") as status:
            with ThreadPoolExecutor(max_workers=discover_workers) as disc_pool:
                disc_futures = {
                    disc_pool.submit(_discover_with_status, key, source): idx
                    for idx, (key, source) in enumerate(selected)
                }
                for fut in as_completed(disc_futures):
                    idx = disc_futures[fut]
                    key, source, files = fut.result()
                    if files:
                        discovered_by_index[idx] = (key, source, files)
                    with completed_lock:
                        done = completed_count
                    status.update(
                        f"[dim]Discovering[/] [bold]{done}/{len(selected)}[/bold]"
                        f" source(s) … "
                        f"[yellow]{sum(len(f) for _, _, f in discovered_by_index.values()):,}[/]"
                        f" file(s) so far"
                    )

    # Rebuild in the original selection order so output is deterministic.
    discovered: list[tuple[str, Source, list[Path]]] = [
        discovered_by_index[i]
        for i in sorted(discovered_by_index)
    ]

    total_files = sum(len(f) for _, _, f in discovered)

    if total_files == 0:
        print("No history files found under any selected source", file=sys.stderr)
        stats_flag = _opt(args, "stats", False)
        if as_json:
            if stats_flag:
                _emit_json_payload(
                    {"findings": [], "stats": _stats_payload_multi([])},
                    output, 0)
            else:
                print("[]")
        else:
            ui.stage(1, "warn", "DISCOVER", f"{len(selected)} source(s)",
                     "no history files", err=True)
            ui.stage(2, "skip", "SCAN", "nothing to scan")
            ui.stage(3, "ok", "FINDINGS", "no secrets found")
            if stats_flag:
                _show_stats(_stats_payload_multi([]))
            ui.stage(4, "skip", "REDACT", "nothing to redact")
            ui.stage(5, "skip", "ROTATE", "nothing to rotate")
            ui.contribute_line()
        return 0

    if not as_json:
        ui.stage(1, "ok", "DISCOVER", f"{len(discovered)} source(s)",
                 f"{total_files} file(s)")

    # Phase 2: scan all sources concurrently.  Each source is independent
    # (separate root, separate files, separate ignore set) so there is no
    # shared mutable state between source-level workers.
    #
    # Thread budget: source-level concurrency is capped at 4.  Each source
    # internally spins up its own _scan_all thread pool (up to 8 file
    # workers), giving at most 4*8 = 32 threads alive at one time — well
    # within the practical limit for local I/O without hammering the GIL.
    #
    # Progress bar safety: Rich's Live.update() must only be called from one
    # thread at a time.  A threading.Lock serialises every call to
    # progress.advance() and progress.detection() so the Live display is
    # never touched from two workers simultaneously.
    #
    # Result ordering: futures are mapped to their original index in
    # `discovered` and results are re-inserted by that index so the findings
    # table output is deterministic regardless of completion order.

    per_source_by_index: dict[
        int,
        tuple[str, Source, list[Path], dict, int, int, list[Path]]
    ] = {}
    total_strings = 0
    total_suppressed = 0
    total_truncated: list[Path] = []

    t0 = time.perf_counter()
    if as_json:
        scan_workers = min(_SOURCE_WORKERS_CAP, len(discovered))
        with ThreadPoolExecutor(max_workers=scan_workers) as scan_pool:
            def _scan_json_source(
                key: str, source: Source, files: list[Path]
            ) -> tuple[str, Source, list[Path], dict, int, int, list[Path]]:
                """Run a full source scan; safe to call from a thread."""
                ignores = (
                    ignore_mod.IgnoreSet() if no_ignore
                    else ignore_mod.load([source.root, Path.cwd()])
                )
                found_by_file, strings_scanned, suppressed, truncated = _scan(
                    source,
                    files,
                    ignores,
                    exclude_rules=exclude_rules,
                    only_rules=only_rules,
                )
                return (
                    key, source, files, found_by_file,
                    strings_scanned, suppressed, truncated
                )

            scan_futures = {
                scan_pool.submit(_scan_json_source, key, source, files): idx
                for idx, (key, source, files) in enumerate(discovered)
            }
            for scan_fut in as_completed(scan_futures):
                idx = scan_futures[scan_fut]
                per_source_by_index[idx] = scan_fut.result()
    else:
        progress_lock = threading.Lock()

        with ui.scan_progress(total_files) as progress:
            def _scan_tty_source(
                key: str, source: Source, files: list[Path]
            ) -> tuple[str, Source, list[Path], dict, int, int, list[Path]]:
                """Run a full source scan with thread-safe progress updates.

                All calls to progress.advance() and progress.detection() are
                serialised through progress_lock so that Rich's Live display
                is never updated from two threads at the same time.
                """
                ignores = (
                    ignore_mod.IgnoreSet() if no_ignore
                    else ignore_mod.load([source.root, Path.cwd()])
                )

                # Wrap the shared progress object with lock-protected callbacks
                # rather than passing the raw object to _scan.  This keeps the
                # locking concern contained here instead of spreading it into
                # the inner _scan/_scan_all path.
                class _LockedProgress:
                    def advance(self_inner, current: str) -> None:
                        with progress_lock:
                            progress.advance(current)

                    def detection(
                        self_inner,
                        rule_display: str,
                        masked: str,
                        location: str,
                    ) -> None:
                        with progress_lock:
                            progress.detection(rule_display, masked, location)

                found_by_file, strings_scanned, suppressed, truncated = _scan(
                    source,
                    files,
                    ignores,
                    _LockedProgress(),
                    exclude_rules=exclude_rules,
                    only_rules=only_rules,
                )
                return (
                    key, source, files, found_by_file,
                    strings_scanned, suppressed, truncated
                )

            scan_workers = min(_SOURCE_WORKERS_CAP, len(discovered))
            with ThreadPoolExecutor(max_workers=scan_workers) as scan_pool:
                scan_futures = {
                    scan_pool.submit(_scan_tty_source, key, source, files): idx
                    for idx, (key, source, files) in enumerate(discovered)
                }
                for scan_fut in as_completed(scan_futures):
                    idx = scan_futures[scan_fut]
                    per_source_by_index[idx] = scan_fut.result()

    # Rebuild in the original discovery order for deterministic output.
    per_source: list[tuple[str, Source, list[Path], dict, int, int, list[Path]]] = [
        per_source_by_index[i] for i in sorted(per_source_by_index)
    ]
    for _k, _s, _f, _fbf, strings_scanned, suppressed, truncated in per_source:
        total_strings += strings_scanned
        total_suppressed += suppressed
        total_truncated.extend(truncated)

    elapsed = time.perf_counter() - t0

    if as_json:
        payload: list[dict] = []
        blast_radius: list[dict] = []
        for _key, source, _files, found_by_file, _sc, _sup, _tr in per_source:
            payload.extend(_json_payload(found_by_file, source))
            if report:
                blast_radius.extend(_blast_radius_payload(found_by_file))
        # Match single-source run(): scan-budget cap is reported, never silent.
        if total_truncated:
            print(
                f"warning: {len(total_truncated)} file(s) exceeded the scan budget "
                f"and were truncated",
                file=sys.stderr,
            )
        _warn_leftover_backups_multi([s for _k, s, *_ in per_source],
                                     as_json=True)
        if as_sarif:
            return _emit_sarif(payload, output, total_suppressed)
        stats = _stats_payload_multi(per_source) if getattr(args, "stats", False) else None
        if report:
            result: JsonObject = {
                "findings": payload,
                "blast_radius": blast_radius,
            }
            if stats is not None:
                result["stats"] = stats
            return _emit_json_payload(
                result,
                output,
                total_suppressed,
            )
        if stats is not None:
            return _emit_json_payload(
                {
                    "findings": payload,
                    "stats": stats,
                },
                output,
                total_suppressed,
            )
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
        if getattr(args, "stats", False):
            empty_stats = _stats_payload_multi(per_source)
            if output is not None:
                _write_text(output, json.dumps(
                    {"findings": [], "stats": empty_stats}, indent=2) + "\n")
                print(f"0 finding(s) written to {output}", file=sys.stderr)
            _show_stats(empty_stats)
        ui.stage(4, "skip", "REDACT", "nothing to redact")
        ui.stage(5, "skip", "ROTATE", "nothing to rotate")
        _warn_leftover_backups_multi([s for _k, s, *_ in per_source],
                                     as_json=False)
        ui.contribute_line()
        return 0

    grand = sum(len(items) for _k, _s, fbf in dirty for items in fbf.values())
    ui.stage(3, "fail", "FINDINGS",
             f"{grand} secret(s) across {len(dirty)} source(s)")

    # Display tables per source without writing the fixed overflow report
    # path (that would clobber across sources). One aggregated report after.
    combined_payload: JsonList = []
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
    stats_payload = _stats_payload_multi(per_source) if getattr(args, "stats", False) else None
    if output is not None:
        output_payload: JsonPayload = combined_payload
        if stats_payload is not None:
            output_payload = {
                "findings": combined_payload,
                "stats": stats_payload,
            }
        _write_text(output, json.dumps(output_payload, indent=2) + "\n")
        ui.warn_line(f"{len(combined_payload)} finding(s) also written to {output}")
    elif needs_overflow:
        report = Path.cwd() / DEFAULT_REPORT_NAME
        _write_text(report, _text_report_multi(combined_payload))
        ui.warn_line(
            f"full multi-source findings ({grand}) written to {report}"
        )

    if stats_payload is not None:
        _show_stats(stats_payload)

    if _opt(args, "fix", False):
        return _fix_all_sources(args, dirty)

    dirty_names = ", ".join(k for k, _s, _f in dirty)
    ui.stage(4, "skip", "REDACT",
             f"skipped — run with --fix to redact in place (.bak backups)  "
             f"(dirty: {dirty_names})")
    ui.stage(5, "warn", "ROTATE", "these keys are still live")
    # Flatten across sources — do not merge by Path (collisions across roots).
    ui.rotation_panel(_rotation_items_multi(dirty))
    _warn_leftover_backups_multi([s for _k, s, *_ in per_source], as_json=False)
    ui.contribute_line()
    return 1


def _fix_all_sources(args, dirty: list[tuple[str, Source, dict]]) -> int:
    """Redact every source with findings, one at a time.

    Each source runs the same path a single-source fix does — its own
    _preflight_gates, its own _redact_all, and therefore its own safe_write
    with backup, validation and audit. Nothing is batched across sources and
    no write happens outside safe_write().

    A source that is gate-blocked, declined, or errors does not abort the
    others: finishing the sweep is the point of --all, and stopping early
    would leave the user worse off than the per-source loop they're replacing.
    On a terminal each source needs its own typed REDACT, so the blast radius
    is never hidden behind one blanket confirm.

    Returns 0 only if every source redacted cleanly, else 2.
    """
    interactive = (sys.stdin.isatty() and ui.console.is_terminal
                   if hasattr(sys.stdin, "isatty") else False)

    total = len(dirty)
    redacted: list[str] = []
    unresolved: list[str] = []

    for key, source, found_by_file in dirty:
        source_cls = SOURCES[key]
        src_total = sum(len(v) for v in found_by_file.values())

        if interactive:
            print()
            ui.warn_line(
                f"{key}: {src_total} secret(s) in {len(found_by_file)} file(s) "
                f"under {source.root} — redact now? "
                f"(.bak backups kept; `agentsweep undo --source {key}` reverts)"
            )
            try:
                typed = input(
                    f"  type REDACT to confirm {key} (anything else skips it): "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                unresolved.append(key)
                break
            if typed != "REDACT":
                ui.redact_row("skip", key, "cancelled — nothing written")
                unresolved.append(key)
                continue

        gate_err, _recoverable = _preflight_gates(source, source_cls, args)
        if gate_err is not None:
            unresolved.append(key)
            continue

        rows, errors, _recoverable = _redact_all(
            source=source,
            found_by_file=found_by_file,
            backup=not args.no_backup,
            force=args.force,
            template=_opt(args, "redact_with", None) or REDACT_TEMPLATE,
        )
        for status, path_display, note in rows:
            ui.redact_row(status, f"{key}: {path_display}", note)
        if errors:
            unresolved.append(key)
        else:
            redacted.append(key)

    if unresolved:
        ui.stage(4, "warn", "REDACT",
                 f"{len(redacted)}/{total} source(s) redacted",
                 f"unresolved: {', '.join(unresolved)}")
    else:
        ui.stage(4, "ok", "REDACT", f"{len(redacted)}/{total} source(s) redacted")

    # Every scanned key is still live until rotated — including those under a
    # source we could not redact, who need the guidance most.
    ui.stage(5, "warn", "ROTATE", "redacted locally", "keys live until rotated")
    ui.rotation_panel(_rotation_items_multi(dirty))
    ui.contribute_line()
    return 2 if unresolved else 0


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


def _scan(
    source,
    files,
    ignores,
    progress=None,
    *,
    exclude_rules: set[str] | None = None,
    only_rules: set[str] | None = None,
):
    """Scan all files, wiring the progress bar + live detection feed when a
    progress object is supplied. (A multiprocessing path was evaluated and
    dropped — on Windows the spawn + per-worker regex recompile cost gave
    ~1.1x and risked a re-import fork bomb; see docs/PERF.md.)"""
    def _on_file(f: Path) -> None:
        if progress is not None:
            progress.advance(ui.rel(f, source.root))

    det = getattr(progress, "detection", None) if progress is not None else None

    def _on_finding(fd: Finding) -> None:
        if det is not None and fd.file is not None and fd.line is not None:
            det(fd.display, fd.masked, f"{ui.rel(fd.file, source.root)}:{fd.line}")

    return _scan_all(
        source,
        files,
        ignores=ignores,
        on_file=_on_file,
        on_finding=_on_finding,
        exclude_rules=exclude_rules,
        only_rules=only_rules,
    )


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
    *,
    exclude_rules: set[str] | None = None,
    only_rules: set[str] | None = None,
) -> tuple[Path, list[tuple[int, list, str, Finding]], int, int, bool]:
    """Scan a single file; safe to call from a thread pool worker.

    Returns (path, findings_list, strings_scanned, suppressed_count, truncated).
    `truncated` is True when the per-file scan budget was hit and the rest of
    the file was skipped. Callbacks are NOT invoked here — the caller dispatches
    them on the main thread after each future completes, so Rich Live is never
    touched from a worker thread.
    """
    exclude_rules = exclude_rules or set()

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
            # --exclude-rule / --only-rule are CLI presentation filters, not
            # ignore-file suppressions, so they do not increment `suppressed`.
            if finding.rule in exclude_rules:
                continue
            if only_rules is not None and finding.rule not in only_rules:
                continue
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
    *,
    exclude_rules: set[str] | None = None,
    only_rules: set[str] | None = None,
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
            _, items, sc, sup, trunc = _scan_file(
                source,
                f,
                ignores,
                exclude_rules=exclude_rules,
                only_rules=only_rules,
            )
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
            pool.submit(
                _scan_file,
                source,
                f,
                ignores,
                exclude_rules=exclude_rules,
                only_rules=only_rules,
            ): f
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

def _group_findings(found_by_file: dict) -> dict:
    """Group findings by masked secret for blast-radius reporting."""

    groups = {}

    for path, items in found_by_file.items():
        for line_num, _kp, _val, finding in items:
            key = finding.masked

            if key not in groups:
                groups[key] = {
                    "rule": finding.rule,
                    "display": finding.display,
                    "masked": finding.masked,
                    "locations": [],
                }

            groups[key]["locations"].append({
                "file": str(path),
                "line": line_num,
            })

    return groups

def _json_payload(found_by_file: dict, source: Source) -> JsonList:
    payload: JsonList = []
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


def _stats_payload(found_by_file: dict,
                   source_key: str | None = None) -> JsonObject:
    by_rule: Counter[str] = Counter()
    total = 0
    for items in found_by_file.values():
        for _line_num, _keypath, _value, finding in items:
            by_rule[finding.rule] += 1
            total += 1
    return {
        "total_findings": total,
        "by_rule": {rule: by_rule[rule] for rule in sorted(by_rule)},
        "by_source": ({source_key: total} if (source_key and total) else {}),
    }


def _stats_payload_multi(
    per_source: list[tuple[str, Source, list[Path], dict, int, int, list[Path]]]
) -> JsonObject:
    by_rule: Counter[str] = Counter()
    by_source: Counter[str] = Counter()
    total = 0

    for key, _source, _files, found_by_file, _sc, _sup, _tr in per_source:
        src_total = sum(len(items) for items in found_by_file.values())
        if src_total:
            by_source[key] += src_total
        total += src_total
        for items in found_by_file.values():
            for _line_num, _keypath, _value, finding in items:
                by_rule[finding.rule] += 1

    return {
        "total_findings": total,
        "by_rule": {rule: by_rule[rule] for rule in sorted(by_rule)},
        "by_source": {source: by_source[source] for source in sorted(by_source)},
    }


def _show_stats(stats: JsonObject) -> None:
    ui.console.print("  Stats", style="bold cyan")
    ui.console.print(f"    total findings: {stats['total_findings']}")
    by_rule = stats["by_rule"]
    if isinstance(by_rule, dict):
        for rule, count in by_rule.items():
            ui.console.print(f"    rule:{rule}  {count}")
    by_source = stats.get("by_source")
    if isinstance(by_source, dict):
        for source, count in by_source.items():
            ui.console.print(f"    source:{source}  {count}")


SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
_PROJECT_URL = "https://github.com/Ishannaik/agent-sweep"

def _blast_radius_payload(found_by_file: dict) -> list[dict]:
    groups = _group_findings(found_by_file)
    report = []

    for group in groups.values():
        report.append({
            "provider": group["display"],
            "rule": group["rule"],
            "masked": group["masked"],
            "occurrences": len(group["locations"]),
            "locations": group["locations"],
            "rotation": ROTATION_GUIDANCE.get(group["rule"]),
        })

    return report


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


def _emit_json_payload(payload: JsonPayload, output: Path | None,
                       suppressed: int) -> int:
    """Shared JSON emission for single- and multi-source scans."""

    findings: JsonList = cast(JsonList, payload["findings"]) if isinstance(payload, dict) else payload
    count = len(findings)
    code = 0 if count == 0 else 1

    if output is not None:
        _write_text(output, json.dumps(payload, indent=2) + "\n")
        print(f"{count} finding(s) written to {output}", file=sys.stderr)
        return code

    flood = (
        count > JSON_FLOOD_LIMIT
        and getattr(sys.stdout, "isatty", lambda: False)()
    )

    if flood:
        target = Path.cwd() / DEFAULT_JSON_NAME
        _write_text(target, json.dumps(payload, indent=2) + "\n")
        print(
            f"{count} findings — too many to print; written to {target}\n"
            f"  view with: cat {DEFAULT_JSON_NAME} | python -m json.tool",
            file=sys.stderr,
        )
        return code

    print(json.dumps(payload, indent=2))

    if suppressed:
        print(f"({suppressed} suppressed by .agentsweepignore)", file=sys.stderr)

    return code

def _output_json(
    found_by_file: dict,
    source: Source,
    output: Path | None,
    suppressed: int,
    report: bool = False,
    stats: bool = False,
) -> int:
    """Emit JSON output, optionally including a blast-radius report."""

    findings = _json_payload(found_by_file, source)
    stats_payload = _stats_payload(found_by_file, source_key=source.name) if stats else None

    if report:
        payload: JsonObject = {
            "findings": findings,
            "blast_radius": _blast_radius_payload(found_by_file),
        }
        if stats_payload is not None:
            payload["stats"] = stats_payload
        return _emit_json_payload(
            payload,
            output,
            suppressed,
        )

    if stats_payload is not None:
        return _emit_json_payload(
            {
                "findings": findings,
                "stats": stats_payload,
            },
            output,
            suppressed,
        )

    return _emit_json_payload(findings, output, suppressed)


def _show_findings(found_by_file: dict, source: Source,
                   output: Path | None, *, stats: JsonObject | None = None) -> None:
    """Human findings table — capped on a real terminal so a huge scan can't
    bury the screen; the full set always goes to a report file in that case
    (or to -o if given)."""
    rows = _table_rows(found_by_file)
    on_tty = ui.console.is_terminal
    capped = on_tty and len(rows) > MAX_TABLE_ROWS

    if output is not None:
        findings = _json_payload(found_by_file, source)
        output_payload: JsonPayload = findings
        if stats is not None:
            output_payload = {
                "findings": findings,
                "stats": stats,
            }
        _write_text(output, json.dumps(output_payload,
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


def _leftover_backups(source: Source) -> list[Path]:
    """Existing .bak sidecars under the source's roots.

    Each still holds the pre-redaction plaintext secret — safe_write writes
    it before replacing the file, and only `purge` deletes it. Same discovery
    undo/purge use, so scan flags exactly what they would act on.
    """
    return sorted({p for root in source.roots() if root.exists()
                   for pat in _BACKUP_GLOBS
                   for p in root.rglob(pat)})


def _warn_leftover_backups(source: Source, as_json: bool) -> None:
    """After a scan, note any .bak sidecars still holding plaintext secrets.

    A user who ran `fix` but not `purge` is not actually clean — the secret
    lives on in the backup. A scan that finds nothing in the redacted files
    would otherwise report an all-clear over those live secrets. Existence and
    count only; the .bak contents are not scanned or shown.
    """
    _emit_backup_warning(len(_leftover_backups(source)), as_json)


def _warn_leftover_backups_multi(sources: list[Source], as_json: bool) -> None:
    """Aggregate leftover-.bak warning across the sources a --all scan visited.

    scan --all is the CI-facing entry point (and what the pre-commit hook
    runs), so it must flag leftover backups too. Counts distinct .bak paths so
    sources sharing a root can't double-count.
    """
    baks = {p for s in sources for p in _leftover_backups(s)}
    _emit_backup_warning(len(baks), as_json)


def _emit_backup_warning(count: int, as_json: bool) -> None:
    if not count:
        return
    msg = (f"{count} leftover .bak backup(s) still contain plaintext secrets "
           f"— run `agentsweep purge` after rotating, or `agentsweep undo` to "
           f"restore them")
    if as_json:
        print(f"warning: {msg}", file=sys.stderr)
    else:
        ui.warn_line(msg)


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
    template: str = REDACT_TEMPLATE,
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

        redactions = _build_redactions(items, template)
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


def _build_redactions(
    items: list[tuple[int, list, str, Finding]],
    template: str = REDACT_TEMPLATE,
) -> list[tuple[int, list, str]]:
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
            new_val = new_val[:start] + template.format(rule=fd.rule) + new_val[end:]
        redactions.append((line_num, list(kp_tuple), new_val))
    return redactions
