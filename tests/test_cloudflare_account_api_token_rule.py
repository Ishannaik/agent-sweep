"""Regression coverage for Cloudflare account API tokens (cfat_ prefix)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402


def _token(body: str = "a" * 40, checksum: str = "0" * 8) -> str:
    return "cfat" "_" + body + checksum


def test_detects_cloudflare_account_api_token_and_includes_rotation_guidance():
    findings = scan_text(_token())

    assert [finding.rule for finding in findings] == ["cloudflare-account-api-token"]
    assert "Cloudflare" in ROTATION_GUIDANCE["cloudflare-account-api-token"]


def test_cloudflare_account_api_token_length_is_exact():
    assert scan_text(_token(body="a" * 39)) == []
    assert scan_text(_token(checksum="0" * 7)) == []
    assert scan_text(_token(body="a" * 41)) == []


def test_cloudflare_account_api_token_checksum_must_be_hex():
    assert scan_text(_token(checksum="g" * 8)) == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _token(),
        "-" + _token(),
        _token() + "z",
        _token() + "-",
    ],
)
def test_cloudflare_account_api_token_rejects_word_and_dash_embeds(embedded: str):
    assert scan_text(embedded) == []
