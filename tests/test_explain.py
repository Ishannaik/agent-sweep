"""agentsweep explain: read-only lookup into scanner.RULES / ROTATION_GUIDANCE.

Covers a known regex-backed rule id, a known function-based detector id
(bip39-mnemonic, present in scanner.DETECTOR_IDS but not scanner.RULES),
--list, the unknown-id error path, and the argparse usage-error path when
neither a rule_id nor --list is given.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import main  # noqa: E402
from agentsweep.scanner import DETECTOR_IDS, ROTATION_GUIDANCE, RULES  # noqa: E402


def test_explain_known_rule_prints_display_pattern_and_guidance(capsys):
    code = main(["explain", "aws-access-key"])
    out = capsys.readouterr().out

    assert code == 0
    assert "AWS access key" in out
    assert "aws-access-key" in out

    pattern = next(p for rid, _d, p in RULES if rid == "aws-access-key")
    assert pattern.pattern in out
    assert ROTATION_GUIDANCE["aws-access-key"] in out


def test_explain_matches_every_registered_rule(capsys):
    """Every RULES entry resolves cleanly, with its own guidance, not just
    one hand-picked id."""
    for rule_id, display, pattern in RULES:
        code = main(["explain", rule_id])
        out = capsys.readouterr().out

        assert code == 0, f"{rule_id} should exit 0"
        assert display in out
        assert pattern.pattern in out

        guidance = ROTATION_GUIDANCE.get(rule_id)
        assert guidance is not None, f"{rule_id} is missing rotation guidance"
        assert guidance in out


def test_explain_detector_id_resolves_without_a_pattern(capsys):
    """bip39-mnemonic is function-based: in DETECTOR_IDS, not RULES."""
    assert "bip39-mnemonic" in DETECTOR_IDS
    assert not any(rid == "bip39-mnemonic" for rid, _d, _p in RULES)

    code = main(["explain", "bip39-mnemonic"])
    out = capsys.readouterr().out

    assert code == 0
    assert "bip39-mnemonic" in out
    assert "function-based detector" in out
    assert "no static regex pattern" in out
    assert ROTATION_GUIDANCE["bip39-mnemonic"] in out


def test_explain_list_prints_every_id_once(capsys):
    code = main(["explain", "--list"])
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line]
    expected = sorted({rid for rid, _d, _p in RULES} | set(DETECTOR_IDS))

    assert code == 0
    assert lines == expected
    assert len(lines) == len(set(lines))
    assert "bip39-mnemonic" in lines
    assert "aws-access-key" in lines


def test_explain_list_wins_over_an_extraneous_rule_id(capsys):
    """--list takes precedence even if a rule_id is also passed: assert the
    actual list output appears, not just a zero exit code."""
    code = main(["explain", "aws-access-key", "--list"])
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line]
    expected = sorted({rid for rid, _d, _p in RULES} | set(DETECTOR_IDS))

    assert code == 0
    assert lines == expected


def test_explain_unknown_rule_id_exits_2(capsys):
    code = main(["explain", "not-a-real-rule-xyz"])
    err = capsys.readouterr().err

    assert code == 2
    assert "not-a-real-rule-xyz" in err
    assert "explain --list" in err


def test_explain_with_no_args_exits_2(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["explain"])
    err = capsys.readouterr().err

    assert exc_info.value.code == 2
    assert "rule_id is required" in err


def test_explain_rejects_source_and_root_flags(capsys):
    """Read-only: explain takes no --source/--root, unlike the scan verbs."""
    with pytest.raises(SystemExit) as exc_info:
        main(["explain", "aws-access-key", "--source", "codex"])
    assert exc_info.value.code == 2

    with pytest.raises(SystemExit) as exc_info:
        main(["explain", "aws-access-key", "--root", "/tmp"])
    assert exc_info.value.code == 2


def test_explain_does_not_scan(capsys):
    """No FINDINGS/pipeline banner should ever appear — pure dict lookup."""
    code = main(["explain", "--list"])
    out = capsys.readouterr().out

    assert code == 0
    assert "FINDINGS" not in out
    assert "SECRET (masked)" not in out
