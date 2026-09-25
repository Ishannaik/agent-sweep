"""--fail-on scopes the "findings found" exit code (1) to specific rule ids.

Findings from unlisted rules are still reported; they just don't fail the run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import cli  # noqa: E402
from agentsweep import menu as menu_mod  # noqa: E402
from agentsweep.cli import _get_completion_parser, main  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
_SECRET_LINE = (
    '{"type":"user","message":{"content":[{"type":"text",'
    f'"text":"key={AWS_KEY} and token {GH_TOKEN}"' + "}]}}\n"
)
_AWS_ONLY_LINE = (
    '{"type":"user","message":{"content":[{"type":"text",'
    f'"text":"key={AWS_KEY}"' + "}]}}\n"
)
_CODEX_LINE = f'{{"type":"message","role":"user","content":"token {GH_TOKEN}"}}\n'


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg" / "config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("AGENTSWEEP_NO_UPDATE", "1")
    monkeypatch.delenv("GROK_HOME", raising=False)
    return home


def _mkroot(tmp_path: Path, line: str = _SECRET_LINE) -> Path:
    root = tmp_path / "history"
    root.mkdir(exist_ok=True)
    (root / "session.jsonl").write_text(line, encoding="utf-8")
    return root


def _scan_json(root: Path, extra: list[str], capsys):
    code = main(["scan", "--root", str(root), "--json", *extra])
    return code, json.loads(capsys.readouterr().out)


def test_listed_rule_finding_exits_1(tmp_path, capsys):
    code, payload = _scan_json(
        _mkroot(tmp_path), ["--fail-on", "aws-access-key"], capsys
    )

    assert code == 1
    assert {item["rule"] for item in payload} == {"aws-access-key", "github-pat"}


def test_unlisted_rule_findings_are_reported_but_exit_0(tmp_path, capsys):
    root = _mkroot(tmp_path, _AWS_ONLY_LINE)

    code, payload = _scan_json(root, ["--fail-on", "github-pat"], capsys)

    assert code == 0
    assert {item["rule"] for item in payload} == {"aws-access-key"}


def test_without_fail_on_any_finding_still_exits_1(tmp_path, capsys):
    code, _payload = _scan_json(_mkroot(tmp_path, _AWS_ONLY_LINE), [], capsys)

    assert code == 1


def test_clean_scan_stays_0_with_fail_on(tmp_path, capsys):
    root = _mkroot(tmp_path, '{"type":"user","message":"nothing here"}\n')

    code, payload = _scan_json(root, ["--fail-on", "aws-access-key"], capsys)

    assert code == 0
    assert payload == []


@pytest.mark.parametrize(
    "flags",
    [
        ["--fail-on", "github-pat,aws-access-key"],
        ["--fail-on", "github-pat", "--fail-on", "aws-access-key"],
        ["--fail-on", " github-pat , aws-access-key ,"],
    ],
    ids=["comma", "repeated", "whitespace"],
)
def test_comma_separated_and_repeatable(tmp_path, capsys, flags):
    root = _mkroot(tmp_path, _AWS_ONLY_LINE)

    code, _payload = _scan_json(root, flags, capsys)

    assert code == 1


@pytest.mark.parametrize("value", ["not-a-rule", "aws-access-key,not-a-rule"])
def test_unknown_rule_id_errors_out(tmp_path, capsys, value):
    root = _mkroot(tmp_path)

    with pytest.raises(SystemExit) as exc_info:
        main(["scan", "--root", str(root), "--json", "--fail-on", value])

    assert exc_info.value.code == 2
    assert "not-a-rule" in capsys.readouterr().err


def test_sarif_output_respects_fail_on(tmp_path, capsys):
    root = _mkroot(tmp_path, _AWS_ONLY_LINE)
    argv = ["scan", "--root", str(root), "--format", "sarif"]

    assert main([*argv, "--fail-on", "github-pat"]) == 0
    assert main([*argv, "--fail-on", "aws-access-key"]) == 1
    capsys.readouterr()


def test_human_output_respects_fail_on(tmp_path, capsys):
    root = _mkroot(tmp_path, _AWS_ONLY_LINE)
    argv = ["scan", "--root", str(root), "--no-color"]

    assert main([*argv, "--fail-on", "github-pat"]) == 0
    out = capsys.readouterr().out
    assert "aws-access-key" in out  # still reported

    assert main([*argv, "--fail-on", "aws-access-key"]) == 1
    capsys.readouterr()


def _seed_all_sources(home: Path) -> None:
    claude = home / ".claude" / "projects"
    claude.mkdir(parents=True)
    (claude / "session.jsonl").write_text(_AWS_ONLY_LINE, encoding="utf-8")
    codex = home / ".codex" / "sessions" / "2026" / "01" / "01"
    codex.mkdir(parents=True)
    (codex / "rollout-test.jsonl").write_text(_CODEX_LINE, encoding="utf-8")


@pytest.mark.parametrize("machine", [True, False], ids=["json", "human"])
def test_scan_all_respects_fail_on(_isolated_home, capsys, machine):
    _seed_all_sources(_isolated_home)
    argv = ["scan", "--all", "--detected"] + (["--json"] if machine else [])

    assert main([*argv, "--fail-on", "slack-bot"]) == 0
    assert main([*argv, "--fail-on", "github-pat"]) == 1  # found in codex only
    capsys.readouterr()


def test_interactive_scan_still_offers_redaction_when_fail_on_masks_exit(
    tmp_path, monkeypatch, capsys
):
    root = _mkroot(tmp_path, _AWS_ONLY_LINE)
    offered = []
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr(
        menu_mod,
        "offer_redaction",
        lambda args, source, found_by_file: offered.append(found_by_file),
    )

    code = main(["scan", "--root", str(root), "--fail-on", "github-pat"])
    capsys.readouterr()

    assert code == 0
    assert len(offered) == 1


def test_completion_parser_registers_fail_on_with_rule_completer():
    parser = _get_completion_parser()
    subparsers = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )

    for name in ("scan", "fix"):
        actions = {
            option: action
            for action in subparsers.choices[name]._actions
            for option in action.option_strings
        }
        assert getattr(actions["--fail-on"], "completer", None) is not None
