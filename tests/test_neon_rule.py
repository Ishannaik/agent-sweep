"""Regression coverage for Neon role passwords (npg_ prefix)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402


def _password(body_length: int = 12) -> str:
    return "npg" "_" + "aB3dE6gH9jKm"[:body_length]


def test_detects_neon_role_password_and_includes_rotation_guidance():
    findings = scan_text(_password())

    assert [finding.rule for finding in findings] == ["neon-role-password"]
    assert "Neon" in ROTATION_GUIDANCE["neon-role-password"]


def test_neon_role_password_length_is_bounded():
    assert scan_text(_password(11)) == []
    assert scan_text(_password(12) + "z") == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _password(),
        "-" + _password(),
        _password() + "z",
        _password() + "-",
    ],
)
def test_neon_role_password_rejects_word_and_dash_embeds(embedded: str):
    assert scan_text(embedded) == []
