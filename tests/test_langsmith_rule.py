"""Regression coverage for LangSmith API keys (lsv2_pt_ / lsv2_sk_ prefixes)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import _PREFILTER, ROTATION_GUIDANCE, scan_text  # noqa: E402


def _key(kind: str = "pt", body: int = 32, tail: int = 10) -> str:
    """Build a synthetic key by concatenation so no live-looking value is stored."""
    return "lsv2_" + kind + "_" + ("a1b2c3d4" * 8)[:body] + "_" + "0123456789"[:tail]


@pytest.mark.parametrize("kind", ["pt", "sk"])
def test_detects_both_prefixes_and_includes_rotation_guidance(kind: str):
    key = _key(kind)
    findings = scan_text(key)

    assert [f.rule for f in findings] == ["langsmith-api-key"]
    assert findings[0].value == key
    assert "smith.langchain.com" in ROTATION_GUIDANCE["langsmith-api-key"]


def test_detects_key_in_env_assignment_and_quotes():
    key = _key()
    for text in (f"LANGCHAIN_API_KEY={key}", f'api_key="{key}"', f"x-api-key: {key}"):
        findings = scan_text(text)
        assert [f.rule for f in findings] == ["langsmith-api-key"], text
        assert findings[0].value == key


def test_body_and_tail_lengths_are_exact():
    assert scan_text(_key(body=31)) == []
    assert scan_text(_key(body=33)) == []
    assert scan_text(_key(tail=9)) == []
    assert scan_text(_key() + "1") == []


@pytest.mark.parametrize(
    "text",
    [
        "lsv2_xx_" + "a" * 32 + "_" + "b" * 10,  # unknown prefix kind
        "lsv2_pt_" + "A" * 32 + "_" + "b" * 10,  # uppercase body
        "lsv2_pt_" + "a" * 32 + "-" + "b" * 10,  # wrong separator
        "lsv2_pt_" + "a" * 32 + "b" * 10,  # missing separator
        "lsv2_pt_" + "a" * 128,  # one long run, no tail
        "lsv2_" + "a" * 32 + "_" + "b" * 10,  # missing kind
    ],
)
def test_rejects_lookalikes(text: str):
    assert scan_text(text) == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _key(),
        "-" + _key(),
        "_" + _key(),
        _key() + "z",
        _key() + "-",
        _key() + "_",
    ],
)
def test_rejects_word_and_dash_embeds(embedded: str):
    assert scan_text(embedded) == []


def test_prefilter_admits_every_matching_prefix():
    anchors = _PREFILTER["langsmith-api-key"]
    for kind in ("pt", "sk"):
        assert any(a in _key(kind) for a in anchors)
