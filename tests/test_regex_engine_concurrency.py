"""End-to-end source/pipeline parity and repeated threaded-scan checks."""

from __future__ import annotations

import json
from pathlib import Path

from _regex_engine_support import run_file_scan
from test_regex_engine_parity import ALL_FIXTURES


def _write_synthetic_codex_history(root: Path) -> None:
    root.mkdir()
    for file_index in range(8):  # >4 forces pipeline._scan_all's thread pool
        records = [
            {
                "role": "user",
                "message": {"content": f"aws {ALL_FIXTURES['aws-access-key']}"},
            },
            {
                "role": "assistant",
                "nested": [{"text": f"openai {ALL_FIXTURES['openai']}"}],
            },
            {
                "role": "user",
                "message": {"content": f"github {ALL_FIXTURES['github-pat']}"},
            },
            {
                "role": "assistant",
                "message": {"content": "中AKIAIOSFODNN7EXAMPLE中 benign\x00text"},
            },
        ]
        content = "".join(
            json.dumps(record, ensure_ascii=False) + "\n" for record in records
        )
        (root / f"session-{file_index:02}.jsonl").write_text(content, encoding="utf-8")


def _first(result: dict) -> dict:
    return result["attempts"][0]


def test_source_to_pipeline_file_parity_and_filters(tmp_path: Path) -> None:
    root = tmp_path / "codex"
    _write_synthetic_codex_history(root)

    stdlib = run_file_scan(root, mode="stdlib", workers=4)
    auto = run_file_scan(root, mode="auto", workers=4)
    no_re2_auto = run_file_scan(root, mode="auto", workers=4, block_re2=True)

    assert _first(stdlib) == _first(auto)
    assert _first(stdlib) == _first(no_re2_auto)
    assert no_re2_auto["summary"]["effective_engine_mode"] == "stdlib"

    filtered = run_file_scan(
        root,
        mode="auto",
        workers=4,
        exclude_rules=["github-pat"],
        only_rules=["aws-access-key", "openai", "github-pat"],
    )
    assert {row[3] for row in _first(filtered)["records"]} == {
        "aws-access-key",
        "openai",
    }


def test_threaded_file_scans_are_deterministic_for_every_worker_count(
    tmp_path: Path,
) -> None:
    root = tmp_path / "codex"
    _write_synthetic_codex_history(root)

    # The production cap is currently eight. Keep this list explicit so the
    # test covers the required 1/2/4/max matrix if the cap is tuned later.
    from agentsweep.pipeline import _SCAN_WORKERS

    expected: dict[str, dict] = {}
    for mode in ("stdlib", "auto"):
        for workers in sorted({1, 2, 4, _SCAN_WORKERS}):
            result = run_file_scan(root, mode=mode, workers=workers, repeats=30)
            attempts = result["attempts"]
            hashes = {attempt["finding_hash"] for attempt in attempts}
            records = {
                json.dumps(attempt["records"], ensure_ascii=False)
                for attempt in attempts
            }
            assert len(hashes) == 1, (mode, workers)
            assert len(records) == 1, (mode, workers)
            assert not attempts[0]["truncated"]
            expected.setdefault(mode, attempts[0])
            assert attempts[0] == expected[mode]

    assert expected["stdlib"] == expected["auto"]
