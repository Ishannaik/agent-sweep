"""Regression coverage for Neon role passwords (npg_ prefix)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402


def _password(body_length: int = 12) -> str:
    """Generate a synthetic Neon role password fixture with a given body length."""
    return "npg_" + "a" * body_length


def test_detects_neon_role_password_and_includes_rotation_guidance():
    """Verify standard Neon role password detection and inclusion of rotation guidance."""
    findings = scan_text(_password())

    assert [finding.rule for finding in findings] == ["neon-role-password"]
    assert "Neon" in ROTATION_GUIDANCE["neon-role-password"]


def test_neon_role_password_length_is_bounded():
    """Verify that Neon role passwords respect the minimum (12) and maximum (64) length boundaries."""
    assert scan_text(_password(11)) == []
    assert [finding.rule for finding in scan_text(_password(64))] == [
        "neon-role-password"
    ]
    assert scan_text(_password(65)) == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _password(),
        "-" + _password(),
        _password(64) + "z",
        _password() + "-",
    ],
)
def test_neon_role_password_rejects_word_and_dash_embeds(embedded: str):
    """Verify that adjacent word characters and dashes prevent false positive match boundaries."""
    assert scan_text(embedded) == []


def test_neon_role_password_redaction_replaces_the_exposed_span():
    """Verify that detected Neon role passwords in environment variables are correctly redacted."""
    from agentsweep.pipeline import _build_redactions

    password = _password()
    value = "PGPASSWORD=" + password
    findings = scan_text(value)
    assert findings, "fixture must produce a finding"

    items = [(1, [], value, f) for f in findings]
    [(_line, _kp, new_value)] = _build_redactions(items)

    assert password not in new_value
    assert "[REDACTED:neon-role-password]" in new_value
    assert new_value == "PGPASSWORD=[REDACTED:neon-role-password]"
