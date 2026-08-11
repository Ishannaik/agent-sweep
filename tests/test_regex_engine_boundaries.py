"""Boundary, Unicode, newline, NUL, and mixed-backend parity coverage."""

from __future__ import annotations

import importlib.util

import pytest

from _regex_engine_support import run_text_scan
from test_mnemonic import VALID_12
from test_regex_engine_parity import ALL_FIXTURES


RE2_INSTALLED = importlib.util.find_spec("re2") is not None
AWS = ALL_FIXTURES["aws-access-key"]


def _rules(result: dict, index: int) -> set[str]:
    return {finding[0] for finding in result["results"][index]}


@pytest.mark.parametrize(
    ("text", "expect_aws"),
    [
        ("", False),
        ("AKIA" + "A" * 15, False),  # one character short
        (AWS[:-1], False),
        ("A" + AWS, False),
        (AWS + "A", False),
        ("1" + AWS, False),
        (AWS + "1", False),
        ("(" + AWS + ")", True),
        (" " + AWS + " ", True),
        ("\n" + AWS + "\n", True),
        ("\r\n" + AWS + "\r\n", True),
        ("\r" + AWS + "\r", True),
        ("\x00" + AWS + "\x00", True),
        ("中" + AWS + "中", False),
        ("é" + AWS + "é", False),
        ("Ａ" + AWS + "Ａ", False),
        ("😀" + AWS + "😀", True),
        ("e\u0301" + AWS + "e\u0301", False),
    ],
)
def test_boundary_and_unicode_cases_match_stdlib(text: str, expect_aws: bool) -> None:
    stdlib = run_text_scan([text], mode="stdlib")
    auto = run_text_scan([text], mode="auto")

    assert stdlib["results"] == auto["results"]
    assert ("aws-access-key" in _rules(stdlib, 0)) is expect_aws


@pytest.mark.skipif(not RE2_INSTALLED, reason="requires optional google-re2 extra")
def test_mixed_backend_overlap_and_mnemonic_parity() -> None:
    # AWS is selected for RE2; OpenAI is a lookahead fallback. Include a
    # BIP-39 detector and Unicode/line ending noise in one realistic string.
    text = (
        "assistant says: 中\r\n"
        + AWS
        + "\nopenai="
        + ALL_FIXTURES["openai"]
        + "\x00\nwallet: "
        + VALID_12
        + "\n"
    )
    stdlib = run_text_scan([text], mode="stdlib", force_all=True)
    auto = run_text_scan([text], mode="auto", force_all=True)

    assert stdlib["results"] == auto["results"]
    assert {"aws-access-key", "openai", "bip39-mnemonic"} <= _rules(auto, 0)


@pytest.mark.skipif(not RE2_INSTALLED, reason="requires optional google-re2 extra")
def test_boundary_guard_keeps_re2_from_overmatching_unicode_words() -> None:
    auto = run_text_scan(["中" + AWS + "中"], mode="auto", include_inventory=True)
    aws = next(
        entry for entry in auto["inventory"] if entry["rule_id"] == "aws-access-key"
    )

    assert aws["selected_backend"] == "re2"
    assert aws["semantic_guard"] is True
    assert "aws-access-key" not in _rules(auto, 0)
