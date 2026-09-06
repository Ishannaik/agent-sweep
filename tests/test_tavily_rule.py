"""Regression coverage for Tavily API keys (tvly- prefix)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402


def _key(body_length: int = 40) -> str:
    """Generate a synthetic Tavily API key string with the specified body length."""
    return "tvly-" + "A" * body_length


def test_detects_tavily_api_key_and_includes_rotation_guidance():
    """Verify standard Tavily API key detection and presence of rotation instructions."""
    findings = scan_text(_key())

    assert [finding.rule for finding in findings] == ["tavily-api-key"]
    assert findings[0].value == _key()
    assert "app.tavily.com" in ROTATION_GUIDANCE["tavily-api-key"]


def test_tavily_api_key_length_is_bounded():
    """Verify that Tavily keys outside the exact 40-character body boundary are ignored."""
    assert scan_text(_key(39)) == []
    assert scan_text(_key(41)) == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _key(),
        "-" + _key(),
        _key() + "z",
        _key() + "-",
    ],
)
def test_tavily_api_key_rejects_word_and_dash_embeds(embedded: str):
    """Verify that boundary characters like adjacent words or dashes prevent false matches."""
    assert scan_text(embedded) == []


def test_tavily_api_key_redaction_replaces_the_exposed_span():
    """Verify that detected Tavily API keys are correctly replaced by the redaction marker."""
    from agentsweep.pipeline import _build_redactions

    key = _key()
    value = "export TAVILY_API_KEY=" + key
    findings = scan_text(value)
    assert findings, "fixture must produce a finding"

    items = [(1, [], value, f) for f in findings]
    [(_line, _kp, new_value)] = _build_redactions(items)

    assert key not in new_value
    assert "[REDACTED:tavily-api-key]" in new_value
    assert new_value == "export TAVILY_API_KEY=[REDACTED:tavily-api-key]"
