"""Regression coverage for legacy Pinecone project API keys."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402


def _key(body_length: int = 104) -> str:
    return "pc" "sk_" + "A" * body_length


def test_detects_pinecone_api_key_and_includes_rotation_guidance():
    findings = scan_text(_key())

    assert [finding.rule for finding in findings] == ["pinecone-api-key"]
    assert "Pinecone console" in ROTATION_GUIDANCE["pinecone-api-key"]


def test_pinecone_api_key_length_is_bounded():
    assert scan_text(_key(63)) == []
    assert scan_text(_key(129)) == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _key(),
        "-" + _key(),
        _key(128) + "z",
        _key() + "-",
    ],
)
def test_pinecone_api_key_rejects_word_and_dash_embeds(embedded: str):
    assert scan_text(embedded) == []
