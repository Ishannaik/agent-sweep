"""Regression coverage for Resend API keys (re_ prefix)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import (  # noqa: E402
    _PREFILTER,
    ROTATION_GUIDANCE,
    scan_text,
)


def _key(head: str = "a" * 8, tail: str = "b" * 24) -> str:
    return "re" + "_" + head + "_" + tail


def test_detects_resend_api_key_and_includes_rotation_guidance():
    findings = scan_text(_key())

    assert [finding.rule for finding in findings] == ["resend-api-key"]
    assert "Resend" in ROTATION_GUIDANCE["resend-api-key"]


def test_resend_api_key_is_prefilter_gated():
    assert "resend-api-key" in _PREFILTER


def test_resend_api_key_segment_lengths_are_exact():
    assert scan_text(_key(head="a" * 7)) == []
    assert scan_text(_key(head="a" * 9)) == []
    assert scan_text(_key(tail="b" * 23)) == []
    assert scan_text(_key(tail="b" * 25)) == []


@pytest.mark.parametrize("ambiguous", ["0", "O", "I", "l"])
def test_resend_api_key_body_is_base58(ambiguous: str):
    assert scan_text(_key(head=ambiguous + "a" * 7)) == []
    assert scan_text(_key(tail=ambiguous + "b" * 23)) == []


@pytest.mark.parametrize(
    "text",
    [
        "re_",
        "re_match",
        "re" + "_" + "a" * 32,  # single segment, no inner underscore
        "store_" + _key()[3:],  # prefix embedded in an identifier
    ],
)
def test_resend_api_key_ignores_generic_re_prefixes(text: str):
    assert [f for f in scan_text(text) if f.rule == "resend-api-key"] == []


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
def test_resend_api_key_rejects_word_and_dash_embeds(embedded: str):
    assert scan_text(embedded) == []
