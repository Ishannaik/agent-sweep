"""Regression coverage for Tavily search API keys."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402


def _key(body_length: int = 36, dev: bool = False) -> str:
    # Split literals via f-string interpolation so security scanners (GitGuardian,
    # push-protection) never flag the test file for hardcoded secret patterns.
    prefix = f"{'tv'}ly-dev-" if dev else f"{'tv'}ly-"
    return prefix + "A" * body_length


@pytest.mark.parametrize("dev", [False, True])
def test_detects_tavily_api_key_and_includes_rotation_guidance(dev: bool) -> None:
    token = _key(36, dev=dev)
    findings = scan_text(token)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "tavily-api-key"
    assert finding.display == "Tavily API key"
    assert finding.value == token
    assert finding.masked.startswith("tvly-")
    assert finding.span == (0, len(token))

    guidance = ROTATION_GUIDANCE["tavily-api-key"]
    assert "Tavily dashboard" in guidance
    assert "https://app.tavily.com/" in guidance


@pytest.mark.parametrize("dev", [False, True])
def test_tavily_api_key_length_is_bounded(dev: bool) -> None:
    # Tavily keys require between 32 and 64 alphanumeric characters after prefix.
    assert scan_text(_key(31, dev=dev)) == []
    assert scan_text(_key(32, dev=dev)) != []
    assert scan_text(_key(40, dev=dev)) != []
    assert scan_text(_key(64, dev=dev)) != []
    assert scan_text(_key(65, dev=dev)) == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _key(36, dev=False),
        "-" + _key(36, dev=False),
        "_" + _key(36, dev=False),
        _key(64, dev=False) + "z",
        _key(36, dev=False) + "-",
        _key(36, dev=False) + "_",
        "z" + _key(36, dev=True),
        "-" + _key(36, dev=True),
        "_" + _key(36, dev=True),
        _key(64, dev=True) + "z",
        _key(36, dev=True) + "-",
        _key(36, dev=True) + "_",
    ],
)
def test_tavily_api_key_rejects_word_and_dash_embeds(embedded: str) -> None:
    assert scan_text(embedded) == []


@pytest.mark.parametrize(
    "template",
    [
        'TAVILY_API_KEY="{key}"',
        "export TAVILY_API_KEY={key}",
        '{{"tavily_api_key": "{key}"}}',
        "tavily_api_key: {key}",
        "url = 'https://api.tavily.com/search?api_key={key}'",
    ],
)
@pytest.mark.parametrize("dev", [False, True])
def test_tavily_api_key_matches_realistic_contexts(template: str, dev: bool) -> None:
    token = _key(40, dev=dev)
    snippet = template.format(key=token)
    findings = scan_text(snippet)

    assert len(findings) == 1
    assert findings[0].rule == "tavily-api-key"
    assert findings[0].value == token


def test_tavily_api_key_supports_mixed_alphanumeric_charset() -> None:
    # Split prefix so scanner/GitGuardian does not trigger on contiguous secret string
    body = "A1b2C3d4" + "E5f6G7h8" + "I9j0K1l2" + "M3n4O5p6"
    token = f"{'tv'}ly-" + body
    findings = scan_text(token)

    assert len(findings) == 1
    assert findings[0].rule == "tavily-api-key"
    assert findings[0].value == token
