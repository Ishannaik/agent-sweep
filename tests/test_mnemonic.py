"""Seed-phrase detector: BIP-39 checksum + Electrum HMAC validation."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import mnemonic  # noqa: E402
from agentsweep.scanner import scan_text  # noqa: E402


# Canonical BIP-39 test vectors (public reference values, not secrets).
VALID_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
VALID_24 = ("abandon " * 23 + "art").strip()
# Same words, broken checksum: 12x abandon does NOT validate.
INVALID_12 = ("abandon " * 12).strip()


def _electrum_seed() -> str:
    """Deterministically brute-force a phrase that fails the BIP-39
    checksum but carries a valid Electrum seed-version tag ('01')."""
    base = ["abandon"] * 11
    for w in mnemonic.WORDS:
        words = base + [w]
        if mnemonic._electrum_version_ok(words) and not mnemonic._bip39_checksum_ok(
            words
        ):
            return " ".join(words)
    raise AssertionError("no electrum-tagged phrase found in 2048 candidates")


def test_valid_12_word_vector_detected():
    findings = scan_text(f"my wallet backup is {VALID_12} keep it safe")
    assert [f.rule for f in findings] == ["bip39-mnemonic"]
    assert findings[0].value == VALID_12
    assert "abandon" in findings[0].masked and "about" in findings[0].masked


def test_ascii_lowercase_fast_path_matches_default():
    text = f"BACKUP: {VALID_12.upper()}"
    assert mnemonic.detect_mnemonics(text) == mnemonic.detect_mnemonics(
        text, text.lower()
    )


def test_valid_24_word_vector_detected_as_one_finding():
    findings = scan_text(VALID_24)
    assert [f.rule for f in findings] == ["bip39-mnemonic"]
    assert "[24 words]" in findings[0].masked


def test_invalid_checksum_not_detected():
    assert not [f for f in scan_text(INVALID_12) if f.rule == "bip39-mnemonic"]


def test_electrum_seed_detected():
    seed = _electrum_seed()
    findings = scan_text(f"electrum says: {seed}")
    assert [f.rule for f in findings] == ["bip39-mnemonic"]


def test_natural_english_not_detected():
    prose = (
        "I think we should all just try to manage our time better and "
        "wonder how other people seem to act on every little thing"
    )
    assert not [f for f in scan_text(prose) if f.rule == "bip39-mnemonic"]


def test_multiline_phrase_detected():
    text = VALID_12.replace(" ", "\n", 5)  # first words on their own lines
    findings = scan_text(text)
    assert [f.rule for f in findings] == ["bip39-mnemonic"]


def test_masked_never_contains_middle_words():
    findings = scan_text(VALID_12)
    middle = VALID_12.split()[1:-1]
    for word_pos, word in enumerate(middle):
        # 'abandon' repeats; just confirm the masked form is the compact
        # first…last shape, not the phrase.
        assert findings[0].masked.count(" ") <= 3
    assert "…" in findings[0].masked or "..." in findings[0].masked


def test_redaction_end_to_end(tmp_path, monkeypatch):
    import json

    from agentsweep import pipeline
    from agentsweep.cli import main

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))

    root = tmp_path / "history"
    root.mkdir()
    session = root / "s.jsonl"
    session.write_text(
        json.dumps(
            {
                "message": {
                    "content": [{"type": "text", "text": f"backup: {VALID_12} ok?"}]
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    code = main(["--root", str(root), "--fix", "--force"])
    assert code == 0
    content = session.read_text(encoding="utf-8")
    assert "abandon" not in content
    assert "[REDACTED:bip39-mnemonic]" in content


def test_no_quadratic_blowup_on_wordy_text():
    import time

    # 50KB of wordlist words that never validate: worst case for windowing.
    text = ("abandon " * 6250).strip()
    t0 = time.perf_counter()
    scan_text(text)
    assert time.perf_counter() - t0 < 2.0


# Regression: the cheap reject must count every separator `_GAP` accepts.
# A tab- or period-joined phrase used to be skipped before tokenizing
# because the old counter only looked at space/newline/comma/semicolon.
TAB_12 = "\t".join(VALID_12.split())
PERIOD_12 = ".".join(VALID_12.split())


def test_tab_separated_phrase_detected():
    assert [f.rule for f in mnemonic.detect_mnemonics(TAB_12)] == ["bip39-mnemonic"]


def test_period_joined_phrase_detected():
    assert [f.rule for f in mnemonic.detect_mnemonics(PERIOD_12)] == ["bip39-mnemonic"]
