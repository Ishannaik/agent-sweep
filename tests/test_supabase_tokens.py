"""Behavioural tests for Supabase sensitive-token detection.

Two rules are under test:

* ``supabase-access-token`` -- ``sbp_`` then exactly 40 lowercase hex chars.
* ``supabase-secret-key`` -- ``sb_secret_`` then 22 base64url chars, a literal
  ``_`` separator, then 8 base64url chars.

Neither may match while embedded in a longer ``[A-Za-z0-9_-]`` run. A plain
``\\b`` anchor is not enough: ``-`` is a non-word char, so ``\\b`` would happily
report ``sbp_<hex>-``. Legacy Supabase JWTs stay with the existing ``jwt``
rule, and the intentionally-public ``sb_publishable_<22>_<8>`` key must never
be reported.

Fixture values are split with an explicit ``+`` on purpose: the source file
must never hold a contiguous credential-shaped token, or GitHub push
protection (and agent-sweep itself) would flag the repo. The full specimens
exist only at runtime.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import scan_text  # noqa: E402

ACCESS_RULE = "supabase-access-token"
SECRET_RULE = "supabase-secret-key"
SENSITIVE_RULES = (ACCESS_RULE, SECRET_RULE)

# sbp_ + 40 lowercase hex.
ACCESS_TOKEN = "sbp_" + "a1" * 20
# sb_secret_ + 22 base64url + _ + 8 base64url. The two bodies deliberately
# stick to [A-Za-z0-9] (no _ or -) so the structural separator stays
# unambiguous under the greedy {22}/{8} quantifiers.
SECRET_KEY = "sb_secret_" + "a1" * 11 + "_" + "b2" * 4
# Intentionally public: sb_publishable_ + 22 + _ + 8.
PUBLISHABLE_KEY = "sb_publishable_" + "c3" * 11 + "_" + "d4" * 4


def _rejection_variants(token: str, body_char: str) -> dict[str, str]:
    """Mutations of ``token`` that its own rule must refuse to report.

    ``body_char`` is legal inside that rule's body, so the too-long case stays
    well formed right past the length limit. Each case kills a different
    sloppy regex: the length variants kill a missing length anchor, the
    word-char embeds kill a rule with no boundary guard at all, and the ``-``
    embeds kill a naive ``\\b`` (``-`` is a non-word char, so ``\\b`` still
    fires beside it). Both sides are exercised independently.
    """
    return {
        "too-short": token[:-1],
        "too-long": token + body_char,
        "left-word-embed": "q" + token,
        "left-dash-embed": "-" + token,
        "right-word-embed": token + "z",
        "right-dash-embed": token + "-",
    }


REJECTION_PARAMS = [
    pytest.param(rule_id, sample, id=f"{rule_id}-{label}")
    for rule_id, token, body_char in (
        (ACCESS_RULE, ACCESS_TOKEN, "0"),
        (SECRET_RULE, SECRET_KEY, "Z"),
    )
    for label, sample in _rejection_variants(token, body_char).items()
]


@pytest.mark.parametrize(
    "rule_id, token",
    [
        pytest.param(ACCESS_RULE, ACCESS_TOKEN, id="access-token"),
        pytest.param(SECRET_RULE, SECRET_KEY, id="secret-key"),
    ],
)
def test_supabase_rule_detects_exact_token(rule_id: str, token: str) -> None:
    """Each exact format is attributed to its contracted rule id exactly once,
    carrying the full matched value (not masked, truncated or grown)."""
    findings = scan_text(token)
    values = [f.value for f in findings if f.rule == rule_id]
    assert values == [token], (
        f"{rule_id}: expected exactly one finding equal to the whole token "
        f"(len {len(token)}); got {[(f.rule, f.value) for f in findings]}"
    )


@pytest.mark.parametrize("rule_id, sample", REJECTION_PARAMS)
def test_supabase_rule_rejects_misshapen_or_embedded(rule_id: str, sample: str) -> None:
    offenders = [(f.rule, f.value) for f in scan_text(sample) if f.rule == rule_id]
    assert not offenders, f"{rule_id}: must not match {sample!r}; got {offenders}"


def test_supabase_publishable_key_is_not_sensitive() -> None:
    """A valid-shaped publishable key is public by design, so neither
    sensitive Supabase rule may report it."""
    offenders = [
        (f.rule, f.value)
        for f in scan_text(PUBLISHABLE_KEY)
        if f.rule in SENSITIVE_RULES
    ]
    assert not offenders, (
        f"publishable key {PUBLISHABLE_KEY!r} must not be reported; got {offenders}"
    )
