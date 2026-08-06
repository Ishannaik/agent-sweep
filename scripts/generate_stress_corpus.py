#!/usr/bin/env python3
"""Generate deterministic, synthetic JSONL corpora for Issue #90 benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
from collections import Counter
from pathlib import Path


PROFILES = (
    "benign_low_hit",
    "anchor_heavy_no_hit",
    "hit_heavy",
    "realistic_mixed",
    "many_small_strings",
    "few_large_strings",
    "skewed_files",
    "adversarial",
    "multi_source",
)
_GENERATOR_VERSION = 2


def _record_size(profile: str) -> int:
    if profile == "many_small_strings":
        return 192
    if profile == "few_large_strings":
        # Stays below scanner._MAX_SCAN_CHARS after JSON decoding.
        return 850_000
    if profile == "adversarial":
        return 64_000
    return 8_000


def _file_count(profile: str, target_bytes: int, record_size: int) -> int:
    if profile == "few_large_strings":
        return max(8, math.ceil(target_bytes / record_size))
    if profile == "many_small_strings":
        return min(512, max(8, target_bytes // (512 * 1024)))
    if profile in {"skewed_files", "multi_source"}:
        return 64
    return min(128, max(8, target_bytes // (1024 * 1024)))


def _repeat(seed: str, length: int) -> str:
    return (seed * (length // len(seed) + 1))[:length]


def _payload(profile: str, length: int, file_index: int, record_index: int) -> str:
    benign = (
        "Assistant: explain the refactor, preserve tests, and summarize the "
        "result. def calculate_total(items): return sum(items)\n"
    )
    anchors = (
        "github token authorization curl gitlab stripe secret configuration "
        "ghp_" + "x" * 35 + " AKIA" + "A" * 15 + " near-miss log entry\n"
    )
    ascii_candidates = (
        "AKIA" + "A" * 15 + "|ASIA" + "A" * 15 + "|ghp_" + "x" * 35
        + "|gho_" + "x" * 35 + "|ghs_" + "x" * 35 + "|hf_" + "x" * 33
        + "|npm_" + "x" * 35 + "|xoxb-" + "x" * 9 + "|xoxp-" + "x" * 9
        + "|AIza" + "x" * 34 + "|GOCSPX-" + "x" * 27 + "|SK" + "a" * 31 + "|"
    )
    hits = (
        "aws=AKIAIOSFODNN7EXAMPLE "
        "github=ghp_" + "a" * 36 + " "
        "openai=sk-proj-" + "a" * 40 + "\n"
    )
    bombs = "curl " * 1_000 + "token=abc123 " * 700 + "deadbeef" * 1_000

    if profile == "benign_low_hit":
        seed = benign
    elif profile == "anchor_heavy_no_hit":
        seed = anchors
    elif profile == "hit_heavy":
        seed = hits
    elif profile == "realistic_mixed":
        prose = _repeat(benign + anchors, length)
        # Agent histories mix prose with compact tool-call/config payloads.
        # The latter retains representative candidate prefixes but has no
        # word separators, so the production BIP-39 separator gate naturally
        # takes its normal cheap path.  This is not a detector toggle.
        structured = _repeat(ascii_candidates, length)
        background = structured if (file_index * 17 + record_index) % 5 < 2 else prose
        if (file_index * 17 + record_index) % 20:
            return background
        # One representative compatible/fallback token set per hit record.
        # Repeating it to fill the record turns a 5% hit rate into thousands
        # of duplicate findings and stops representing normal history data.
        return (hits + background)[:length]
    elif profile == "many_small_strings":
        seed = hits if (file_index + record_index) % 97 == 0 else benign
    elif profile == "few_large_strings":
        # Candidate-heavy failed matches make regex execution dominate JSON
        # decoding. Pipe separators intentionally cannot form a BIP-39 phrase,
        # so the production mnemonic detector exits through its normal,
        # lossless separator gate rather than being disabled for a benchmark.
        seed = ascii_candidates
    elif profile == "skewed_files":
        seed = hits if file_index % 13 == 0 else benign + anchors
    elif profile == "adversarial":
        seed = bombs + "\x00中😀\r\n" + anchors
    else:  # multi_source: source-shaped paths are still ordinary JSONL.
        seed = hits if (file_index + record_index) % 31 == 0 else benign + anchors
    return _repeat(seed, length)


def _corpus_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.jsonl")):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _expected_findings(root: Path) -> tuple[int, str, int, Counter[str]]:
    """Compute an engine-independent regression oracle from synthetic input."""
    # This script starts in a fresh process.  Use the existing stdlib mode as
    # the oracle before importing the scanner; corpus manifests must not bless
    # a mixed-engine result that is being benchmarked.
    os.environ["AGENTSWEEP_REGEX_ENGINE"] = "stdlib"
    from agentsweep.scanner import scan_text
    from agentsweep.sources import CodexSource

    source = CodexSource(root=root)
    digest = hashlib.sha256()
    digest.update(b"[")
    first = True
    per_rule: Counter[str] = Counter()
    findings = 0
    strings = 0
    for path in source.files():
        relative = path.relative_to(root).as_posix()
        for line, keypath, value in source.iter_strings(path):
            strings += 1
            for finding in scan_text(value):
                row = [
                    relative, line, keypath, finding.rule, finding.display,
                    finding.value, finding.masked, finding.span[0], finding.span[1],
                ]
                if not first:
                    digest.update(b",")
                digest.update(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode())
                first = False
                findings += 1
                per_rule[finding.rule] += 1
    digest.update(b"]")
    return findings, digest.hexdigest(), strings, per_rule


def _compatibility_counts(per_rule: Counter[str]) -> tuple[int, int, bool]:
    """Classify expected findings against the locally installed optional engine."""
    from agentsweep.regex_engine import RE2_AVAILABLE, build_rule_registry
    from agentsweep.scanner import _RAW_RULES

    backend = {
        rule_id: pattern.backend_name
        for rule_id, _display, pattern in build_rule_registry(_RAW_RULES, mode="auto")
    }
    # Function-based detectors such as BIP-39 are outside the regex registry.
    compatible = sum(count for rule_id, count in per_rule.items() if backend.get(rule_id) == "re2")
    return compatible, sum(per_rule.values()) - compatible, RE2_AVAILABLE


def _write_corpus(output: Path, profile: str, target_bytes: int, seed: int, files: int) -> dict[str, object]:
    rng = random.Random(seed)
    record_size = _record_size(profile)
    output.mkdir(parents=True, exist_ok=True)
    written = 0
    records = 0
    for file_index in range(files):
        if written >= target_bytes:
            break
        group = f"source-{file_index % 4:02}" if profile == "multi_source" else "sessions"
        path = output / group / f"session-{file_index:04}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            file_target = max(record_size, math.ceil((target_bytes - written) / (files - file_index)))
            if profile == "skewed_files" and file_index % 16 == 0:
                file_target *= 8
            file_written = 0
            record_index = 0
            while file_written < file_target and written < target_bytes:
                payload_size = min(record_size, max(1, file_target - file_written))
                payload = _payload(profile, payload_size, file_index, record_index)
                record = {
                    "type": "synthetic-agent-history",
                    "seed": rng.randrange(1_000_000),
                    "message": {"content": payload, "ordinal": records},
                }
                encoded = (json.dumps(record, ensure_ascii=False) + "\n").encode()
                handle.write(encoded.decode())
                file_written += len(encoded)
                written += len(encoded)
                records += 1
                record_index += 1

    corpus_hash = _corpus_hash(output)
    expected_findings, finding_hash, strings, per_rule = _expected_findings(output)
    compatible_findings, fallback_findings, re2_available = _compatibility_counts(per_rule)
    manifest = {
        "generator_version": _GENERATOR_VERSION,
        "name": profile,
        "seed": seed,
        "target_bytes": target_bytes,
        "actual_bytes": sum(path.stat().st_size for path in output.rglob("*.jsonl")),
        "files": len(list(output.rglob("*.jsonl"))),
        "records": records,
        "strings": strings,
        "expected_findings": expected_findings,
        "compatible_findings": compatible_findings,
        "fallback_findings": fallback_findings,
        "compatibility_re2_available": re2_available,
        "expected_engine": "stdlib",
        "expected_finding_hash": finding_hash,
        "corpus_sha256": corpus_hash,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--size-mib", type=float, default=32.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--files", type=int, help="override deterministic profile file count")
    args = parser.parse_args()
    if args.size_mib <= 0:
        parser.error("--size-mib must be positive")
    if args.output.exists() and any(args.output.iterdir()):
        parser.error(f"refusing to write into non-empty directory: {args.output}")

    target = int(args.size_mib * 1024 * 1024)
    record_size = _record_size(args.profile)
    files = args.files or _file_count(args.profile, target, record_size)
    if files <= 0:
        parser.error("--files must be positive")
    manifest = _write_corpus(args.output, args.profile, target, args.seed, files)
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
