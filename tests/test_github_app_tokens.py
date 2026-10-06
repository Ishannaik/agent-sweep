"""Regression coverage for opaque GitHub App installation tokens."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import scan_text  # noqa: E402


def _stateless_token(repetitions: int) -> str:
    """Build a deliberately low-entropy opaque ghs token for detection tests."""
    return "ghs_" + "APPID_JWT.payload-" * repetitions


def _github_app_findings(text: str):
    return [finding for finding in scan_text(text) if finding.rule == "github-app"]


@pytest.mark.parametrize("repetitions", (3, 30))
def test_stateless_github_app_token_keeps_full_opaque_value_and_span(
    repetitions: int,
) -> None:
    token = _stateless_token(repetitions)
    text = f"before:{token};after"

    findings = _github_app_findings(text)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.value == token
    assert finding.span == (len("before:"), len("before:") + len(token))
    assert finding.masked == token[:6] + "*" * 8 + token[-4:]
    assert "." in token and "_" in token and token.endswith("-")
    if repetitions == 30:
        assert len(token) > 520


@pytest.mark.parametrize("prefix", ("ghs_", "ghu_"))
def test_legacy_github_app_token_still_detected(prefix: str) -> None:
    token = prefix + "a1" * 18

    findings = _github_app_findings(f"token={token};")

    assert [finding.value for finding in findings] == [token]


@pytest.mark.parametrize(
    "text",
    (
        "ghs_" + "a1" * 17 + "a",  # 35-character body: below ghs minimum
        "embeddedghs_" + "a1" * 18,
        "embeddedghu_" + "a1" * 18,
        "ghu_" + "a1" * 18 + "a",  # ghu remains exactly 36 alphanumerics
    ),
)
def test_invalid_or_embedded_github_app_tokens_are_not_detected(text: str) -> None:
    assert not _github_app_findings(text)
