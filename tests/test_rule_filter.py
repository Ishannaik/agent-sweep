from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import _get_completion_parser, main  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
_SECRET_LINE = (
    '{"type":"user","message":{"content":[{"type":"text",'
    f'"text":"key={AWS_KEY} and token {GH_TOKEN}"' + "}]}}\n"
)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def _mkroot(tmp_path: Path) -> Path:
    root = tmp_path / "history"
    root.mkdir(exist_ok=True)
    (root / "session.jsonl").write_text(_SECRET_LINE, encoding="utf-8")
    return root


def _scan_json(root: Path, extra_args: list[str] | None = None, capsys=None):
    code = main(["scan", "--root", str(root), "--json"] + (extra_args or []))
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    return code, payload, captured.err


def test_exclude_rule_drops_matching_findings(tmp_path, capsys):
    root = _mkroot(tmp_path)

    code, payload, _err = _scan_json(
        root,
        extra_args=["--exclude-rule", "aws-access-key"],
        capsys=capsys,
    )

    assert code == 1
    assert {item["rule"] for item in payload} == {"github-pat"}


def test_only_rule_keeps_only_named_rule(tmp_path, capsys):
    root = _mkroot(tmp_path)

    code, payload, _err = _scan_json(
        root,
        extra_args=["--only-rule", "aws-access-key"],
        capsys=capsys,
    )

    assert code == 1
    assert {item["rule"] for item in payload} == {"aws-access-key"}


def test_unknown_rule_id_errors_out(tmp_path):
    root = _mkroot(tmp_path)

    with pytest.raises(SystemExit) as exc_info:
        main(["scan", "--root", str(root), "--json", "--only-rule", "not-a-rule"])

    assert exc_info.value.code == 2


def test_exclude_and_only_rule_are_mutually_exclusive(tmp_path):
    root = _mkroot(tmp_path)

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "scan",
                "--root",
                str(root),
                "--json",
                "--exclude-rule",
                "aws-access-key",
                "--only-rule",
                "github-pat",
            ]
        )

    assert exc_info.value.code == 2


def test_completion_parser_registers_rule_id_completer_for_filters():
    parser = _get_completion_parser()
    subparsers_action = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )

    for name in ("scan", "fix"):
        subparser = subparsers_action.choices[name]
        actions = {
            option: action
            for action in subparser._actions
            for option in action.option_strings
        }
        assert getattr(actions["--exclude-rule"], "completer", None) is not None
        assert getattr(actions["--only-rule"], "completer", None) is not None
