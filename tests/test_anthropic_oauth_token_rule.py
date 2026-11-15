"""Regression coverage for Claude Code OAuth tokens (sk-ant-oatNN prefix)."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import (  # noqa: E402
    _PREFILTER,
    ROTATION_GUIDANCE,
    scan_text,
)


def _token(body: str | None = None, version: str = "01") -> str:
    if body is None:
        body = "A" * 40 + "-" + "b" * 32
    return "sk-ant-" + f"oat{version}-" + body


def test_detects_oauth_token_and_includes_rotation_guidance():
    token = _token()
    findings = scan_text(token)

    assert [f.rule for f in findings] == ["anthropic-oauth-token"]
    assert findings[0].value == token
    assert "claude auth login" in ROTATION_GUIDANCE["anthropic-oauth-token"]


def test_detects_realistic_length_token_inside_text():
    token = _token("a1B2_" * 19)
    findings = scan_text(f'{{"accessToken":"{token}"}}')

    assert [f.rule for f in findings] == ["anthropic-oauth-token"]
    assert findings[0].value == token


def test_api_keys_keep_their_own_rule():
    api = "sk-ant-" + "api03-" + "A" * 40
    assert [f.rule for f in scan_text(api)] == ["anthropic"]


def test_prefilter_anchor_is_a_fixed_literal():
    assert _PREFILTER["anthropic-oauth-token"] == ("sk-ant-oat",)


def test_body_length_is_bounded():
    assert scan_text(_token("a" * 32))
    assert scan_text(_token("a" * 256))
    assert scan_text(_token("a" * 31)) == []
    assert scan_text(_token("a" * 257)) == []


@pytest.mark.parametrize("version", ["1", "001", "ab"])
def test_requires_two_digit_version(version: str):
    assert scan_text(_token(version=version)) == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _token(),
        "-" + _token(),
        "_" + _token(),
        _token("a" * 256) + "z",
        _token("a" * 256) + "-",
        _token("a" * 256) + "_",
    ],
)
def test_rejects_word_and_dash_embeds(embedded: str):
    assert scan_text(embedded) == []


def test_no_catastrophic_backtracking_on_long_near_miss():
    text = ("sk-ant-" + "oat01-" + "a" * 50_000) + "!" + ("sk-ant-oat01-" * 2_000)
    start = time.perf_counter()
    scan_text(text)
    assert time.perf_counter() - start < 2.0
