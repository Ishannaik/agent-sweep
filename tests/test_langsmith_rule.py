"""Regression coverage for LangSmith personal and service API keys."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import (  # noqa: E402
    ROTATION_GUIDANCE,
    _PREFILTER,
    scan_text,
)


def _key(kind: str = "pt", body: str = "a" * 36, tail: str = "b" * 10) -> str:
    return "lsv2_" + kind + "_" + body + "_" + tail


@pytest.mark.parametrize("kind", ["pt", "sk"])
def test_detects_langsmith_personal_and_service_keys(kind: str) -> None:
    findings = scan_text(_key(kind))

    assert [finding.rule for finding in findings] == ["langsmith-api-key"]
    assert "LangSmith" in ROTATION_GUIDANCE["langsmith-api-key"]


def test_detects_single_segment_128_character_key_from_issue() -> None:
    key = "lsv2_" + "pt_" + "0123456789abcdef" * 8

    assert [finding.rule for finding in scan_text(key)] == ["langsmith-api-key"]


@pytest.mark.parametrize(
    "near_miss",
    [
        _key(body="a" * 31, tail=""),
        _key(kind="xx"),
        _key(body="a" * 257, tail=""),
        _key(tail="b" * 257),
        "z" + _key(),
        _key() + "-suffix",
    ],
)
def test_langsmith_key_rejects_invalid_or_out_of_bounds_values(
    near_miss: str,
) -> None:
    assert scan_text(near_miss) == []


def test_langsmith_prefilter_uses_shared_prefix() -> None:
    assert _PREFILTER["langsmith-api-key"] == ("lsv2_",)
