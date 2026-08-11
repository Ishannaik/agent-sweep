"""Smoke-test the synthetic corpus and end-to-end benchmark tooling."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.generate_stress_corpus import _compatibility_counts  # noqa: E402


def test_synthetic_corpus_manifest_and_stdlib_runner(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    generated = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/generate_stress_corpus.py"),
            "--profile",
            "many_small_strings",
            "--size-mib",
            "0.05",
            "--output",
            str(corpus),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["files"] >= 8
    assert manifest["expected_findings"] > 0
    assert (
        manifest["compatible_findings"] + manifest["fallback_findings"]
        == manifest["expected_findings"]
    )
    assert manifest["expected_engine"] == "stdlib"
    assert len(manifest["corpus_sha256"]) == 64

    output = tmp_path / "result.json"
    benchmarked = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/benchmark_regex_engines.py"),
            "--corpus",
            str(corpus),
            "--engines",
            "stdlib",
            "--workers",
            "1",
            "--warmups",
            "0",
            "--trials",
            "1",
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert benchmarked.returncode == 0, benchmarked.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["execution_seed"] == 42
    sample = result["samples"]["stdlib-w1"][0]
    assert sample["correctness_ok"] is True
    assert sample["finding_hash"] == manifest["expected_finding_hash"]


def test_soak_runner_records_stable_hashes(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    generated = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/generate_stress_corpus.py"),
            "--profile",
            "few_large_strings",
            "--size-mib",
            "0.05",
            "--output",
            str(corpus),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    output = tmp_path / "soak.json"
    env = os.environ.copy()
    env["AGENTSWEEP_REGEX_ENGINE"] = "stdlib"
    soaked = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/run_re2_soak.py"),
            "--corpus",
            str(corpus),
            "--workers",
            "1",
            "--rounds",
            "2",
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    assert soaked.returncode == 0, soaked.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["all_finding_hashes_equal"] is True
    assert len(result["samples"]) == 2


def test_function_detector_findings_count_as_fallback() -> None:
    compatible, fallback, _available = _compatibility_counts(
        Counter({"bip39-seed-phrase": 2})
    )

    assert compatible == 0
    assert fallback == 2


def test_compatibility_audit_creates_output_directories(tmp_path: Path) -> None:
    json_path = tmp_path / "json" / "audit.json"
    markdown_path = tmp_path / "markdown" / "audit.md"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/audit_re2_compatibility.py"),
            "--json",
            str(json_path),
            "--markdown",
            str(markdown_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    audit = json.loads(json_path.read_text(encoding="utf-8"))
    covered = sum(rule["fixture_exists"] for rule in audit["rules"])
    assert f"Synthetic fixture coverage: {covered}/{len(audit['rules'])}" in (
        markdown_path.read_text(encoding="utf-8")
    )
