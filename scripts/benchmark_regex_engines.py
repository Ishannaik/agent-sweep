#!/usr/bin/env python3
"""Run reproducible, file-level stdlib vs mixed-RE2 benchmarks.

The parent process alternates independent child processes so thermal drift is
not silently assigned to one engine.  Each child uses the production path:
``CodexSource.files -> iter_strings -> pipeline._scan_all``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

try:
    import resource
except ModuleNotFoundError:  # Windows does not expose POSIX resource APIs.
    resource = None


ROOT = Path(__file__).resolve().parents[1]
_PROCESS_STARTED = time.perf_counter()


def _normalise(found: dict, root: Path) -> list[list[object]]:
    rows: list[list[object]] = []
    for path, entries in found.items():
        for line, keypath, _value, finding in entries:
            rows.append(
                [
                    path.relative_to(root).as_posix(),
                    line,
                    keypath,
                    finding.rule,
                    finding.display,
                    finding.value,
                    finding.masked,
                    finding.span[0],
                    finding.span[1],
                ]
            )
    return rows


def _rss_bytes(usage: object) -> int:
    # macOS reports ru_maxrss in bytes; Linux reports KiB.
    max_rss = int(getattr(usage, "ru_maxrss"))
    return max_rss if sys.platform == "darwin" else max_rss * 1024


def _resource_usage() -> tuple[float, float, int] | None:
    if resource is None:
        return None
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime, usage.ru_stime, _rss_bytes(usage)


def _measure(corpus: Path, workers: int) -> dict[str, object]:
    """Measure one already-imported engine in a fresh Python process."""
    import agentsweep.pipeline as pipeline
    from agentsweep.scanner import ENGINE_SUMMARY, PREFILTER_BACKEND
    from agentsweep.sources import CodexSource

    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    source = CodexSource(root=corpus)
    files = source.files()
    pipeline._SCAN_WORKERS = workers  # type: ignore[attr-defined]  # private production knob
    input_bytes = sum(path.stat().st_size for path in files)
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
    encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    finding_hash = hashlib.sha256(encoded.encode()).hexdigest()
    finding_count = len(rows)
    expected_hash = manifest["expected_finding_hash"]
    expected_count = manifest["expected_findings"]
    if before is None or after is None:
        user_cpu_seconds = system_cpu_seconds = peak_rss = baseline_rss = None
    else:
        user_cpu_seconds = after[0] - before[0]
        system_cpu_seconds = after[1] - before[1]
        peak_rss = after[2]
        baseline_rss = before[2]
    cpu_seconds = (
        user_cpu_seconds + system_cpu_seconds
        if user_cpu_seconds is not None and system_cpu_seconds is not None
        else None
    )
    return {
        "startup_seconds": started - _PROCESS_STARTED,
        "wall_seconds": elapsed,
        "user_cpu_seconds": user_cpu_seconds,
        "system_cpu_seconds": system_cpu_seconds,
        "cpu_utilization_percent": (
            cpu_seconds / elapsed * 100 if cpu_seconds is not None and elapsed else None
        ),
        "peak_rss_bytes": peak_rss,
        "rss_delta_bytes": (
            max(0, peak_rss - baseline_rss)
            if peak_rss is not None and baseline_rss is not None
            else None
        ),
        "input_bytes": input_bytes,
        "throughput_mib_s": input_bytes / (1024 * 1024) / elapsed if elapsed else 0.0,
        "strings_per_s": strings / elapsed if elapsed else 0.0,
        "files_per_s": len(files) / elapsed if elapsed else 0.0,
        "files": len(files),
        "strings": strings,
        "suppressed": suppressed,
        "truncated_files": len(truncated),
        "finding_count": finding_count,
        "finding_hash": finding_hash,
        "expected_finding_count": expected_count,
        "expected_finding_hash": expected_hash,
        "correctness_ok": finding_count == expected_count
        and finding_hash == expected_hash,
        "requested_workers": workers,
        "effective_workers": min(workers, len(files)),
        "engine": ENGINE_SUMMARY,
        "prefilter_backend": PREFILTER_BACKEND,
        "corpus_sha256": manifest["corpus_sha256"],
        "exit_status": 0,
    }


def _child(corpus: Path, workers: int, engine: str) -> dict[str, object]:
    env = os.environ.copy()
    env["AGENTSWEEP_REGEX_ENGINE"] = engine
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--measure",
        "--corpus",
        str(corpus),
        "--workers",
        str(workers),
    ]
    completed = subprocess.run(
        command, text=True, capture_output=True, env=env, check=False
    )
    if completed.returncode:
        raise RuntimeError(
            f"benchmark child failed ({completed.returncode}): {completed.stderr}"
        )
    result = json.loads(completed.stdout)
    engine_data = result["engine"]
    assert isinstance(engine_data, dict)
    if engine == "auto" and int(engine_data["re2_rule_count"]) == 0:
        raise RuntimeError(
            "auto benchmark selected zero RE2 rules; install the fast extra first"
        )
    if not result["correctness_ok"]:
        raise RuntimeError("benchmark finding hash differs from corpus manifest")
    return result


def _safe_command(*command: str) -> str | None:
    try:
        return subprocess.check_output(
            command, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _memory_snapshot(corpus: Path) -> dict[str, object]:
    disk = os.statvfs(corpus)
    return {
        "corpus_filesystem": _safe_command("stat", "-f", "%T", str(corpus)),
        "corpus_disk_total_bytes": disk.f_blocks * disk.f_frsize,
        "corpus_disk_free_bytes": disk.f_bavail * disk.f_frsize,
        "swap_usage": _safe_command("sysctl", "-n", "vm.swapusage"),
        "memory_pressure": _safe_command("memory_pressure"),
    }


def _environment(corpus: Path | None = None) -> dict[str, object]:
    hardware = _safe_command("system_profiler", "SPHardwareDataType")
    safe_hardware = []
    if hardware:
        safe_hardware = [
            line.strip()
            for line in hardware.splitlines()
            if line.strip().startswith(
                (
                    "Model Name:",
                    "Model Identifier:",
                    "Chip:",
                    "Total Number of Cores:",
                    "Memory:",
                )
            )
        ]
    disk = os.statvfs(ROOT)
    battery = _safe_command("pmset", "-g", "batt") or ""
    power_settings = _safe_command("pmset", "-g") or ""
    low_power_lines = [
        line.strip()
        for line in power_settings.splitlines()
        if "lowpowermode" in line.lower()
    ]
    return {
        "started_at_utc": datetime.now(UTC).isoformat(),
        "hardware": safe_hardware,
        "macos": _safe_command("sw_vers"),
        "uname": {
            "sysname": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "logical_cpus": _safe_command("sysctl", "-n", "hw.logicalcpu"),
        "physical_cpus": _safe_command("sysctl", "-n", "hw.physicalcpu"),
        "memory_bytes": _safe_command("sysctl", "-n", "hw.memsize"),
        "python": sys.version,
        "python_executable": Path(sys.executable).name,
        "python_machine": platform.machine(),
        "packages": {
            name: _package_version(name)
            for name in ("google-re2", "pyahocorasick", "pytest-benchmark")
        },
        "git_commit": _safe_command("git", "rev-parse", "HEAD"),
        "git_branch": _safe_command("git", "branch", "--show-current"),
        "git_dirty": bool(_safe_command("git", "status", "--porcelain")),
        "disk_total_bytes": disk.f_blocks * disk.f_frsize,
        "disk_free_bytes": disk.f_bavail * disk.f_frsize,
        "power": "AC" if "AC Power" in battery else "battery-or-unavailable",
        "low_power_mode": low_power_lines,
        "memory_snapshot": _memory_snapshot(corpus) if corpus is not None else None,
    }


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, math.ceil(percentile / 100 * len(ordered)) - 1)
    return ordered[index]


def _stats(samples: list[dict[str, object]]) -> dict[str, float]:
    walls = [_number(sample, "wall_seconds") for sample in samples]
    throughputs = [_number(sample, "throughput_mib_s") for sample in samples]
    median = statistics.median(walls)
    return {
        "median_seconds": median,
        "min_seconds": min(walls),
        "max_seconds": max(walls),
        "p95_seconds": _percentile(walls, 95),
        "mad_seconds": statistics.median(abs(value - median) for value in walls),
        "median_mib_s": statistics.median(throughputs),
    }


def _bootstrap_improvement(
    stdlib: list[dict[str, object]], auto: list[dict[str, object]], seed: int
) -> dict[str, float]:
    rng = random.Random(seed)
    stdlib_walls = [_number(sample, "wall_seconds") for sample in stdlib]
    auto_walls = [_number(sample, "wall_seconds") for sample in auto]
    changes = []
    for _ in range(2_000):
        stdlib_median = statistics.median(
            rng.choice(stdlib_walls) for _ in stdlib_walls
        )
        auto_median = statistics.median(rng.choice(auto_walls) for _ in auto_walls)
        changes.append((stdlib_median / auto_median - 1) * 100)
    return {
        "median_percent": (
            statistics.median(stdlib_walls) / statistics.median(auto_walls) - 1
        )
        * 100,
        "ci95_low_percent": _percentile(changes, 2.5),
        "ci95_high_percent": _percentile(changes, 97.5),
    }


def _number(sample: dict[str, object], field: str) -> float:
    value = sample[field]
    assert isinstance(value, (int, float))
    return float(value)


def _parse_csv(raw: str, *, values: set[str] | None = None) -> list[str]:
    parsed = [part.strip() for part in raw.split(",") if part.strip()]
    if not parsed:
        raise ValueError("empty comma-separated option")
    if values is not None and set(parsed) - values:
        raise ValueError(f"unsupported value(s): {sorted(set(parsed) - values)}")
    return parsed


def _run(args: argparse.Namespace) -> dict[str, object]:
    engines = _parse_csv(args.engines, values={"stdlib", "auto"})
    workers = [int(value) for value in _parse_csv(args.workers)]
    if any(value <= 0 for value in workers):
        raise ValueError("worker counts must be positive")
    if args.warmups < 0 or args.trials <= 0:
        raise ValueError("--warmups must be >= 0 and --trials must be positive")
    manifest = json.loads((args.corpus / "manifest.json").read_text(encoding="utf-8"))
    environment_before = _environment(args.corpus)
    configs = [(engine, worker) for worker in workers for engine in engines]
    rng = random.Random(args.seed)
    samples: dict[str, list[dict[str, object]]] = {
        f"{engine}-w{worker}": [] for engine, worker in configs
    }
    engine_metadata: dict[str, object] = {}
    execution_order = []
    for phase, rounds in (("warmup", args.warmups), ("measure", args.trials)):
        for round_index in range(rounds):
            order = list(configs)
            rng.shuffle(order)
            for engine, worker in order:
                result = _child(args.corpus, worker, engine)
                key = f"{engine}-w{worker}"
                engine_metadata.setdefault(key, result.pop("engine"))
                execution_order.append(
                    {
                        "phase": phase,
                        "round": round_index,
                        "engine": engine,
                        "workers": worker,
                        "wall_seconds": result["wall_seconds"],
                    }
                )
                if phase == "measure":
                    samples[key].append(result)

    summaries = {key: _stats(values) for key, values in samples.items()}
    comparisons = {}
    if {"stdlib", "auto"} <= set(engines):
        for worker in workers:
            comparisons[f"w{worker}"] = _bootstrap_improvement(
                samples[f"stdlib-w{worker}"],
                samples[f"auto-w{worker}"],
                args.seed + worker,
            )
    return {
        "schema_version": 1,
        "environment": {
            "before": environment_before,
            "after": _environment(args.corpus),
        },
        "corpus_manifest": manifest,
        "engines": engines,
        "workers": workers,
        "warmups_per_config": args.warmups,
        "trials_per_config": args.trials,
        "execution_seed": args.seed,
        "execution_order": execution_order,
        "samples": samples,
        "engine_metadata": engine_metadata,
        "summaries": summaries,
        "comparisons": comparisons,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measure", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--workers", default="1,2,4,8")
    parser.add_argument("--engines", default="stdlib,auto")
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--trials", type=int, default=9)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.measure:
        if not args.corpus.is_dir():
            parser.error(f"corpus is not a directory: {args.corpus}")
        print(json.dumps(_measure(args.corpus, int(args.workers))))
        return 0
    if args.output is None:
        parser.error("--output is required for a benchmark run")
    if args.output.exists():
        parser.error(f"refusing to overwrite existing result: {args.output}")
    if not args.corpus.is_dir():
        parser.error(f"corpus is not a directory: {args.corpus}")
    try:
        result = _run(args)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
