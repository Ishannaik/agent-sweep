"""Regression coverage for Stripe webhook endpoint signing secrets."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, scan_text  # noqa: E402

_PREFIX = "wh" + "sec_"


def _secret(body_length: int = 40, *, padding: str = "") -> str:
    return _PREFIX + "A" * body_length + padding


def _rules(text: str) -> list[str]:
    return [finding.rule for finding in scan_text(text)]


def test_detects_stripe_webhook_secret_and_includes_rotation_guidance():
    assert _rules(_secret()) == ["stripe-webhook-secret"]

    guidance = ROTATION_GUIDANCE["stripe-webhook-secret"]
    assert "Roll" in guidance
    assert "dashboard.stripe.com/webhooks" in guidance


@pytest.mark.parametrize("body_length", [32, 40, 64])
def test_stripe_webhook_secret_accepts_bounded_documented_lengths(
    body_length: int,
):
    assert _rules(_secret(body_length)) == ["stripe-webhook-secret"]


@pytest.mark.parametrize("body_length", [31, 65])
def test_stripe_webhook_secret_rejects_out_of_range_lengths(body_length: int):
    assert scan_text(_secret(body_length)) == []


def test_stripe_webhook_secret_accepts_base64_body_and_padding():
    secret = _PREFIX + "Ab9/" * 8 + "=="

    assert _rules(secret) == ["stripe-webhook-secret"]


@pytest.mark.parametrize("suffix", ["===", "=A", "_", "-"])
def test_stripe_webhook_secret_rejects_invalid_suffixes(suffix: str):
    assert scan_text(_secret(32) + suffix) == []


@pytest.mark.parametrize(
    "embedded",
    [
        "z" + _secret(),
        "/" + _secret(),
        "-" + _secret(),
        _secret(64) + "z",
        _secret(64) + "/",
        _secret(64) + "-",
    ],
)
def test_stripe_webhook_secret_rejects_embedded_tokens(embedded: str):
    assert scan_text(embedded) == []


@pytest.mark.parametrize(
    "context",
    [
        'STRIPE_WEBHOOK_SECRET="{secret}"',
        "endpoint_secret = '{secret}'",
        '{{"stripe_webhook_secret": "{secret}"}}',
    ],
)
def test_stripe_webhook_secret_matches_realistic_contexts(context: str):
    assert _rules(context.format(secret=_secret())) == ["stripe-webhook-secret"]
