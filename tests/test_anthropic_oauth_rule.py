"""Regression coverage for Claude Code OAuth tokens (sk-ant-oatNN prefix)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402


def _token(body: str | None = None, version: str = "01") -> str:
    if body is None:
        body = "A" * 40 + "-" + "b" * 32
    return "sk-ant-" + f"oat{version}-" + body


def test_detects_anthropic_oauth_token_and_includes_rotation_guidance():
    token = _token()
    findings = scan_text(token)

    assert [finding.rule for finding in findings] == ["anthropic-oauth-token"]
    assert findings[0].value == token
    assert "claude login" in ROTATION_GUIDANCE["anthropic-oauth-token"]


def test_anthropic_oauth_token_body_length_is_bounded():
    assert scan_text(_token("a" * 64))
    assert scan_text(_token("a" * 256))
    assert scan_text(_token("a" * 63)) == []
    assert scan_text(_token("a" * 257)) == []


@pytest.mark.parametrize("version", ["1", "001", "ab"])
def test_anthropic_oauth_token_requires_two_digit_version(version: str):
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
def test_anthropic_oauth_token_rejects_word_and_dash_embeds(embedded: str):
    assert scan_text(embedded) == []
