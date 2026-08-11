from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import main  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
ANTHROPIC_TOKEN = "sk-ant-api03-" + "A" * 40  # synthetic, non-live test value

SINGLE_SOURCE_LINE = (
    '{"type":"user","message":{"content":[{"type":"text",'
    f'"text":"key={AWS_KEY} token={GH_TOKEN} anthropic={ANTHROPIC_TOKEN}"' + "}]}}\n"
)
CODEX_LINE = f'{{"type":"message","role":"user","content":"token {GH_TOKEN}"' + "}\n"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    appdata = tmp_path / "appdata"
    appdata.mkdir()
    local = tmp_path / "localappdata"
    local.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg / "config"))
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("AGENTSWEEP_NO_UPDATE", "1")
    return home


def _mkroot(tmp_path: Path, content: str = SINGLE_SOURCE_LINE) -> Path:
    root = tmp_path / "history"
    root.mkdir(exist_ok=True)
    (root / "session.jsonl").write_text(content, encoding="utf-8")
    return root


def _seed_claude(home: Path, content: str = SINGLE_SOURCE_LINE) -> Path:
    root = home / ".claude" / "projects"
    root.mkdir(parents=True, exist_ok=True)
    (root / "session.jsonl").write_text(content, encoding="utf-8")
    return root


def _seed_codex(home: Path, content: str = CODEX_LINE) -> Path:
    root = home / ".codex"
    sess = root / "sessions" / "2026" / "01" / "01"
    sess.mkdir(parents=True, exist_ok=True)
    (sess / "rollout-test.jsonl").write_text(content, encoding="utf-8")
    return root


def test_scan_json_stats_nests_summary_under_stats(tmp_path, capsys):
    root = _mkroot(tmp_path)

    code = main(["scan", "--root", str(root), "--json", "--stats"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 1
    assert set(payload) == {"findings", "stats"}
    assert payload["stats"]["total_findings"] == 3
    assert payload["stats"]["by_rule"] == {
        "aws-access-key": 1,
        "github-pat": 1,
        "anthropic": 1,
    }
    assert payload["stats"]["by_source"] == {"claude-code": 3}


def test_scan_human_stats_prints_summary(tmp_path, capsys):
    root = _mkroot(tmp_path)

    code = main(["scan", "--root", str(root), "--stats"])
    captured = capsys.readouterr()

    assert code == 1
    assert "Stats" in captured.out
    assert "total findings: 3" in captured.out
    assert "rule:aws-access-key  1" in captured.out
    assert "rule:github-pat  1" in captured.out
    assert "rule:anthropic  1" in captured.out
    assert "source:claude-code  3" in captured.out


def test_scan_empty_discovery_json_stats(tmp_path, capsys):
    """--json --stats on an empty root emits the standard stats object, not []."""
    root = tmp_path / "empty"
    root.mkdir()

    code = main(["scan", "--root", str(root), "--json", "--stats"])
    captured = capsys.readouterr()

    assert code == 0
    payload = json.loads(captured.out)
    assert payload["findings"] == []
    assert payload["stats"]["total_findings"] == 0
    assert payload["stats"]["by_rule"] == {}
    assert payload["stats"]["by_source"] == {}


def test_scan_clean_stats_writes_output_file(tmp_path, capsys):
    """--stats -o on a clean scan writes {"findings": [], "stats": ...} to file."""
    root = tmp_path / "history"
    root.mkdir()
    (root / "session.jsonl").write_text(
        '{"type":"user","message":{"content":[]}}\n', encoding="utf-8"
    )
    out_file = tmp_path / "report.json"

    code = main(["scan", "--root", str(root), "--stats", "--output", str(out_file)])

    assert code == 0
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["stats"]["total_findings"] == 0
    assert payload["stats"]["by_rule"] == {}
    assert payload["stats"]["by_source"] == {}


def test_scan_all_clean_stats_writes_output_file(tmp_path, _isolated_home, capsys):
    """--all --stats -o on a clean multi-source scan writes the zero-stats payload."""
    _seed_claude(_isolated_home, content='{"type":"user","message":{"content":[]}}\n')
    _seed_codex(
        _isolated_home, content='{"type":"message","role":"user","content":""}\n'
    )
    out_file = tmp_path / "report.json"

    code = main(["scan", "--all", "--stats", "--output", str(out_file)])

    assert code == 0
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["stats"]["total_findings"] == 0
    assert payload["stats"]["by_rule"] == {}
    assert payload["stats"]["by_source"] == {}


def test_stats_sarif_combination_is_rejected(tmp_path, capsys):
    """--stats --format sarif must fail with exit code 2 and a clear message."""
    root = _mkroot(tmp_path)

    code = main(["scan", "--root", str(root), "--stats", "--format", "sarif"])
    captured = capsys.readouterr()

    assert code == 2
    assert "--stats" in captured.err
    assert "SARIF" in captured.err


def test_stats_sarif_combination_is_rejected_all(_isolated_home, capsys):
    """Same rejection applies to scan --all --stats --format sarif."""
    _seed_claude(_isolated_home)

    code = main(["scan", "--all", "--stats", "--format", "sarif"])
    captured = capsys.readouterr()

    assert code == 2
    assert "--stats" in captured.err
    assert "SARIF" in captured.err


def test_scan_all_json_stats_include_per_source_counts(_isolated_home, capsys):
    _seed_claude(_isolated_home)
    _seed_codex(_isolated_home)

    code = main(["scan", "--all", "--json", "--stats"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 1
    assert set(payload) == {"findings", "stats"}
    assert payload["stats"]["total_findings"] == 4
    assert payload["stats"]["by_rule"] == {
        "aws-access-key": 1,
        "github-pat": 2,
        "anthropic": 1,
    }
    assert payload["stats"]["by_source"] == {
        "claude-code": 3,
        "codex": 1,
    }
