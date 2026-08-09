#!/usr/bin/env python3
"""Repeat the production file scan in one process and record RSS stability."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from benchmark_regex_engines import _environment, _normalise, _resource_usage  # noqa: E402


def _current_rss_bytes() -> int | None:
    """Read only this benchmark process's current RSS, when the OS exposes it."""
    try:
        rss_kib = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(os.getpid())],
            text=True,
        ).strip()
        return int(rss_kib) * 1024
    except (OSError, ValueError, subprocess.CalledProcessError):
        return None


def _run(corpus: Path, workers: int, rounds: int) -> dict[str, object]:
    from agentsweep import pipeline
    from agentsweep.scanner import ENGINE_SUMMARY, PREFILTER_BACKEND
    from agentsweep.sources import CodexSource

    if (
        ENGINE_SUMMARY["requested_engine"] == "auto"
        and int(ENGINE_SUMMARY["re2_rule_count"]) == 0
    ):
        raise RuntimeError(
            "auto soak selected zero RE2 rules; install the fast extra first"
        )

    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    source = CodexSource(root=corpus)
    files = source.files()
    pipeline._SCAN_WORKERS = workers  # type: ignore[attr-defined]  # private production knob
    samples = []
    for round_index in range(rounds):
        before = _resource_usage()
        started = time.perf_counter()
        found, strings, suppressed, truncated = pipeline._scan_all(  # type: ignore[attr-defined]
            source,
            files,
            ignores=None,
        )
        elapsed = time.perf_counter() - started
        after = _resource_usage()
        rows = _normalise(found, corpus)
        finding_hash = hashlib.sha256(
            json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        if (len(rows), finding_hash) != (
            manifest["expected_findings"],
            manifest["expected_finding_hash"],
        ):
            raise RuntimeError(f"finding mismatch on soak round {round_index}")
        if before is None or after is None:
            user_cpu_seconds = system_cpu_seconds = peak_rss = None
        else:
            user_cpu_seconds = after[0] - before[0]
            system_cpu_seconds = after[1] - before[1]
            peak_rss = after[2]
        samples.append(
            {
                "round": round_index,
                "wall_seconds": elapsed,
                "user_cpu_seconds": user_cpu_seconds,
                "system_cpu_seconds": system_cpu_seconds,
                "peak_rss_bytes": peak_rss,
                "current_rss_bytes": _current_rss_bytes(),
                "strings": strings,
                "suppressed": suppressed,
                "truncated_files": len(truncated),
                "finding_count": len(rows),
                "finding_hash": finding_hash,
            }
        )

    current = [sample["current_rss_bytes"] for sample in samples]
    known_current = [value for value in current if isinstance(value, int)]
    return {
        "schema_version": 1,
        "environment": _environment(corpus),
        "corpus_manifest": manifest,
        "engine": ENGINE_SUMMARY,
        "prefilter_backend": PREFILTER_BACKEND,
        "workers": workers,
        "rounds": rounds,
        "samples": samples,
        "all_finding_hashes_equal": len({sample["finding_hash"] for sample in samples})
        == 1,
        "current_rss_growth_bytes": (
            max(known_current) - min(known_current) if known_current else None
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.workers <= 0 or args.rounds <= 0:
        parser.error("--workers and --rounds must be positive")
    if args.output.exists():
        parser.error(f"refusing to overwrite existing result: {args.output}")
    if not args.corpus.is_dir():
        parser.error(f"corpus is not a directory: {args.corpus}")
    try:
        result = _run(args.corpus, args.workers, args.rounds)
    except RuntimeError as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
