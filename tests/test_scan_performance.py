"""Pre-filter correctness + catastrophic-input timing for the full rule set."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import _PREFILTER, scan_text  # noqa: E402


# Large single-line inputs that previously summed to multi-second scans.
BOMBS = {
    "repeated-char": "a" * 50000,
    "curl-flood": "curl " * 10000,
    "assignment-flood": "token=abc123 " * 4000,
    "path-flood": "https://" + "x/" * 20000,
    "hex-blob": "deadbeef" * 8000,
}

CURL_AUTH_BOMBS = {
    "curl-auth-header": (
        "curl " * 5000
        + ("x" * 200 + ' --headeX "Authorization: Bearer abcdefgh" ') * 100
    ),
    "curl-auth-user": (
        "curl " * 5000 + ("x" * 200 + " --useX username:password ") * 100
    ),
}


@pytest.mark.parametrize("name", list(BOMBS))
def test_no_catastrophic_scan_time(name):
    t0 = time.perf_counter()
    scan_text(BOMBS[name])
    assert time.perf_counter() - t0 < 1.0, f"{name} scan too slow"


@pytest.mark.parametrize("name", list(CURL_AUTH_BOMBS))
def test_curl_auth_rules_resist_adversarial_backtracking(name):
    t0 = time.perf_counter()
    findings = scan_text(CURL_AUTH_BOMBS[name])
    elapsed = time.perf_counter() - t0

    assert not any(f.rule == name for f in findings), (
        f"{name} produced a false-positive finding"
    )
    assert elapsed < 1.0, f"{name} adversarial scan too slow: {elapsed:.3f}s"


def test_full_scan_of_all_bombs_is_fast():
    t0 = time.perf_counter()
    for text in BOMBS.values():
        scan_text(text)
    # Five pathological 50-80KB inputs back to back. Keyword-gating the
    # context rules took this from ~9s to ~1.6s; the floor is now ~60
    # anchored rules each doing one honest linear pass (no backtracking).
    # 3s leaves headroom for slow CI while still catching the old blowup.
    assert time.perf_counter() - t0 < 3.0


def test_prefilter_literals_are_truly_present_in_fixtures():
    """Every prefiltered rule's own fixture must contain a prefilter literal,
    otherwise the gate would skip a real secret. (Belt-and-suspenders on top
    of the parametrized fixture-detection tests.)"""
    from test_ported_rules import FIXTURES  # type: ignore

    for rule_id, kws in _PREFILTER.items():
        fixture = FIXTURES.get(rule_id)
        if fixture is None:
            continue
        low = fixture.lower()
        assert any(k in low for k in kws), (
            f"{rule_id}: fixture lacks any prefilter literal {kws}"
        )


def test_prefilter_covers_anchored_and_context_rules():
    # Anchored-prefix rules are now gated on their literal anchor too, so a
    # giant non-secret string skips ~all 205 regexes via cheap substring
    # checks instead of full regex passes.
    assert _PREFILTER.get("aws-access-key") == ("akia",)
    assert _PREFILTER.get("github-pat") == ("ghp_",)
    assert _PREFILTER.get("pinecone-api-key") == ("pcsk_",)
    assert _PREFILTER.get("gitlab-pat") == ("glpat-",)
    # Context rules keep their any-of provider keywords.
    assert set(_PREFILTER["jfrog-api-key"]) == {
        "jfrog",
        "artifactory",
        "bintray",
        "xray",
    }
    # Most of the 205 rules now have an anchor; the few without one (short or
    # non-literal leads) simply always run — still correct.
    assert len(_PREFILTER) > 150


def test_prefilter_backend_is_lossless_vs_running_all_rules():
    """The single-pass anchor dispatch must find exactly what running every
    rule would — proving the Aho-Corasick (or fallback) backend drops nothing,
    including overlapping-literal cases like `git` inside `gitlab`."""
    import agentsweep.scanner as sc
    from test_ported_rules import FIXTURES  # type: ignore

    samples = list(FIXTURES.values()) + [
        "just some normal english prose about keys tokens and secrets",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "gitlab and github and git all mentioned here with glpat-a1b2c3a1b2c3a1b2c3ab",
        "",
    ]

    def fp(text):
        return sorted((f.rule, f.span) for f in sc.scan_text(text))

    orig = sc._triggered_indices
    try:
        prefiltered = [fp(s) for s in samples]
        sc._triggered_indices = lambda lowered: set(range(len(sc.RULES)))
        all_rules = [fp(s) for s in samples]
    finally:
        sc._triggered_indices = orig

    assert prefiltered == all_rules


def test_prefilter_backend_named():
    from agentsweep.scanner import PREFILTER_BACKEND

    assert PREFILTER_BACKEND in ("aho-corasick", "substring")


def test_prefilter_does_not_change_findings():
    """Gating must be lossless: a string containing a context keyword still
    runs the rule exactly as before."""
    # snyk rule fires with the keyword present...
    hit = "snyk_token = 12345678-1234-1234-1234-123456789abc"
    assert any(f.rule == "snyk" for f in scan_text(hit))
    # ...and a uuid with no provider keyword nearby does not.
    assert not any(
        f.rule == "snyk" for f in scan_text("12345678-1234-1234-1234-123456789abc")
    )
