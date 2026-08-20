"""Mixed-engine parity tests run in fresh processes for import-time selection."""

from __future__ import annotations

import importlib.util
import random

import pytest

from _regex_engine_support import run_text_scan
from test_ported_rules import FIXTURES


def _core_fixtures() -> dict[str, str]:
    return {
        "aws-access-key": "AKIAIOSFODNN7EXAMPLE",
        "aws-session-token": "ASIA" + "IOSFODNN7EXAMPLE",
        "github-pat": "ghp_" + "a" * 36,
        "github-oauth": "gho_" + "a" * 36,
        "github-app": "ghs_" + "a" * 36,
        "github-fine-grained": "github_pat_" + "a" * 82,
        "stripe-live": "sk_live_" + "a" * 24,
        "stripe-test": "sk_test_" + "a" * 24,
        "openai": "sk-proj-" + "a" * 40,
        "pinecone-api-key": "pc" + "sk_" + "a" * 104,
        "anthropic": "sk-ant-api03-" + "a" * 32,
        "google-api": "AIza" + "a" * 35,
        "google-oauth-client-secret": "GOCSPX-" + "a" * 28,
        "google-service-account-key": (
            '"type": "service_account", "private_key_id": "' + "a" * 40 + '"'
        ),
        "slack-bot": "xoxb-" + "a" * 10,
        "slack-user": "xoxp-" + "a" * 10,
        "slack-webhook": "https://hooks.slack.com/services/T000/B000/abcdefgh",
        "huggingface": "hf_" + "a" * 34,
        "supabase-access-token": "sbp_" + "a1" * 20,
        "supabase-secret-key": "sb_secret_" + "a1" * 11 + "_" + "b2" * 4,
        "jwt": "eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 10,
        "private-key-pem": (
            "-----BEGIN PRIVATE KEY-----\nsynthetic-body\n-----END PRIVATE KEY-----"
        ),
        "db-url-with-password": "postgresql://user:password@example.test/db",
        "neon-role-password": "npg" + "_" + "a" * 12,
        "cloudflare-account-api-token": "cfat" + "_" + "a" * 40 + "0" * 8,
        "npm-token": "npm_" + "a" * 36,
        "pypi-token": "pypi-AgEIcHlwaS5vcmc" + "a" * 50,
        "sendgrid": "SG." + "a" * 22 + "." + "b" * 43,
        "twilio": "SK" + "a" * 32,
        "discord-bot-token": "M" + "a" * 23 + "." + "b" * 6 + "." + "c" * 27,
        "discord-webhook": (
            "https://discord.com/api/webhooks/" + "1" * 17 + "/" + "a" * 60
        ),
    }


ALL_FIXTURES = {**_core_fixtures(), **FIXTURES}
RE2_INSTALLED = importlib.util.find_spec("re2") is not None


def _rules_for(result: dict, input_index: int) -> set[str]:
    return {finding[0] for finding in result["results"][input_index]}


def test_every_current_rule_has_a_synthetic_fixture() -> None:
    registry = run_text_scan([], mode="stdlib", include_inventory=True)
    rule_ids = {entry["rule_id"] for entry in registry["inventory"]}
    assert set(ALL_FIXTURES) == rule_ids

    result = run_text_scan(list(ALL_FIXTURES.values()), mode="stdlib")
    for index, rule_id in enumerate(ALL_FIXTURES):
        assert rule_id in _rules_for(result, index), rule_id


@pytest.mark.skipif(not RE2_INSTALLED, reason="requires optional google-re2 extra")
def test_all_rule_fixtures_have_full_auto_stdlib_parity() -> None:
    texts = list(ALL_FIXTURES.values())
    stdlib = run_text_scan(texts, mode="stdlib")
    auto = run_text_scan(texts, mode="auto")

    assert auto["summary"]["re2_rule_count"] > 0
    assert stdlib["results"] == auto["results"]
    assert stdlib["finding_hash"] == auto["finding_hash"]


@pytest.mark.skipif(not RE2_INSTALLED, reason="requires optional google-re2 extra")
def test_auto_inventory_is_complete_and_auditable() -> None:
    result = run_text_scan([], mode="auto", include_inventory=True)
    inventory = result["inventory"]
    summary = result["summary"]

    assert len(inventory) == len(ALL_FIXTURES)
    assert len({entry["rule_id"] for entry in inventory}) == len(inventory)
    assert (
        sum(entry["selected_backend"] == "re2" for entry in inventory)
        == summary["re2_rule_count"]
    )
    assert all(
        entry["fallback_reason"]
        for entry in inventory
        if entry["selected_backend"] == "stdlib"
    )
    assert any(entry["semantic_guard"] for entry in inventory)


def test_auto_without_re2_is_the_stdlib_oracle() -> None:
    texts = [
        "中" + ALL_FIXTURES["aws-access-key"] + "中",
        ALL_FIXTURES["openai"],
        ALL_FIXTURES["github-pat"],
        "ordinary prose\x00with CRLF\r\n",
    ]
    stdlib = run_text_scan(texts, mode="stdlib")
    no_re2_auto = run_text_scan(texts, mode="auto", block_re2=True)

    assert no_re2_auto["summary"]["re2_available"] is False
    assert no_re2_auto["summary"]["effective_engine_mode"] == "stdlib"
    assert stdlib["results"] == no_re2_auto["results"]


def test_stdlib_mode_forces_every_rule_to_the_oracle() -> None:
    result = run_text_scan([], mode="stdlib", include_inventory=True)

    assert result["summary"]["effective_engine_mode"] == "stdlib"
    assert all(entry["selected_backend"] == "stdlib" for entry in result["inventory"])
    assert all(
        entry["compile_status"] == "not-attempted" for entry in result["inventory"]
    )


def _random_samples(seed: int, count: int) -> list[str]:
    rng = random.Random(seed)
    fixtures = list(ALL_FIXTURES.values())
    atoms = [
        "normal assistant response",
        "def handle(value): return value",
        "INFO token check",
        "中 文",
        "emoji 😀",
        "e\u0301",
        "\x00",
        "\r\n",
        "\n",
        "near-miss ghp_short",
        "curl authorization token",
        "gitlab github stripe secret",
        "ＡＢＣ１２３",
    ]
    texts: list[str] = []
    for _ in range(count):
        parts = [rng.choice(atoms) for _ in range(rng.randint(1, 6))]
        parts.extend(rng.choice(fixtures) for _ in range(rng.randint(0, 5)))
        rng.shuffle(parts)
        texts.append(rng.choice([" ", "\n", "\r\n", "中", "😀"]).join(parts))
    return texts


@pytest.mark.skipif(not RE2_INSTALLED, reason="requires optional google-re2 extra")
def test_ten_thousand_fixed_seed_samples_are_exactly_equal() -> None:
    samples = _random_samples(seed=90210, count=10_000)
    stdlib = run_text_scan(samples, mode="stdlib")
    auto = run_text_scan(samples, mode="auto")

    if stdlib["results"] != auto["results"]:
        first = next(
            index
            for index, pair in enumerate(zip(stdlib["results"], auto["results"]))
            if pair[0] != pair[1]
        )
        pytest.fail(
            f"seed=90210 sample={first}: {samples[first]!r}\n"
            f"stdlib={stdlib['results'][first]!r}\nauto={auto['results'][first]!r}"
        )
    assert stdlib["finding_hash"] == auto["finding_hash"]


@pytest.mark.skipif(not RE2_INSTALLED, reason="requires optional google-re2 extra")
def test_prefilter_is_lossless_in_both_engines() -> None:
    samples = list(ALL_FIXTURES.values()) + _random_samples(seed=7, count=250)
    for mode in ("stdlib", "auto"):
        ordinary = run_text_scan(samples, mode=mode)
        all_rules = run_text_scan(samples, mode=mode, force_all=True)
        assert ordinary["results"] == all_rules["results"], mode
