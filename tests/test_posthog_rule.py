from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402


@pytest.mark.parametrize(
    "suffix",
    [
        "a2b3c4d5e6f7g8h9jAkBmCnDpEqFrGsHtJuKvMwNxPyQzR2x",
        "a2b3c4d5e6f7g8h9jAkBmCnDpEqFrGsHtJuKvMwNxPyQzR2xY",
    ],
)
def test_posthog_personal_api_key_detects_real_lengths(suffix: str) -> None:
    token = f"{'ph'}x_{suffix}"

    assert any(f.rule == "posthog-personal-api-key" for f in scan_text(token))


def test_posthog_personal_api_key_detects_legacy_base62() -> None:
    suffix = "a0b1cOdIeLf2g3h4i5j6k7l8m9n0p1q2r3s4t5u6v7w"
    token = f"{'ph'}x_{suffix}"

    assert any(f.rule == "posthog-personal-api-key" for f in scan_text(token))


def test_posthog_project_key_is_not_personal_api_key() -> None:
    suffix = "a2b3c4d5e6f7g8h9jAkBmCnDpEqFrGsHtJuKvMwNxPyQzR2x"
    token = f"{'ph'}c_{suffix}"

    assert not any(f.rule == "posthog-personal-api-key" for f in scan_text(token))


def test_posthog_rotation_guidance_is_not_us_cloud_only() -> None:
    guidance = ROTATION_GUIDANCE["posthog-personal-api-key"]

    assert "us.posthog.com" not in guidance
    assert "self-hosted" in guidance
