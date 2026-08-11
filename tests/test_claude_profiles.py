"""Claude Code multi-profile discovery via CLAUDE_CONFIG_DIR.

Claude Code stores history under <profile>/projects/. agentsweep historically
scanned only ~/.claude, so a side-project profile (e.g. ~/.claude-personal)
went unscanned. These cover the env override and the default staying put.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline  # noqa: E402
from agentsweep.cli import main  # noqa: E402
from agentsweep.sources import ClaudeCodeSource  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
_LINE = (
    '{"type":"user","message":{"role":"user","content":'
    '[{"type":"text","text":"key=AKIAIOSFODNN7EXAMPLE"}]}}\n'
)


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return home


@pytest.fixture(autouse=True)
def _no_agent_running(monkeypatch):
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))


def _seed_profile(profile_dir: Path, *, age: int = 3700) -> Path:
    projects = profile_dir / "projects" / "proj"
    projects.mkdir(parents=True, exist_ok=True)
    f = projects / "session.jsonl"
    f.write_text(_LINE, encoding="utf-8")
    past = time.time() - age
    os.utime(f, (past, past))
    return f


def test_default_root_unchanged_without_env(_isolate_home):
    assert ClaudeCodeSource().default_root() == _isolate_home / ".claude" / "projects"
    assert ClaudeCodeSource().root == _isolate_home / ".claude" / "projects"


def test_config_dir_env_redirects_root(_isolate_home, monkeypatch):
    custom = _isolate_home / ".claude-personal"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(custom))
    src = ClaudeCodeSource()
    assert src.root == custom / "projects"
    assert src.roots() == [custom / "projects"]


def test_scan_finds_secret_in_custom_profile(_isolate_home, monkeypatch, capsys):
    custom = _isolate_home / ".claude-personal"
    _seed_profile(custom)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(custom))

    code = main(["scan", "--source", "claude-code", "--json"])
    assert code == 1
    findings = json.loads(capsys.readouterr().out)
    assert any(f["rule"] == "aws-access-key" for f in findings)


def test_comma_separated_scans_every_profile(_isolate_home, monkeypatch, capsys):
    a = _isolate_home / ".claude"
    b = _isolate_home / ".claude-work"
    _seed_profile(a)
    _seed_profile(b)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", f"{a},{b}")

    src = ClaudeCodeSource()
    assert set(src.roots()) == {a / "projects", b / "projects"}
    assert len(src.files()) == 2

    code = main(["scan", "--source", "claude-code", "--json"])
    findings = json.loads(capsys.readouterr().out)
    assert code == 1
    assert len(findings) == 2


def test_default_profile_scanned_when_env_unset(_isolate_home, capsys):
    _seed_profile(_isolate_home / ".claude")
    code = main(["scan", "--source", "claude-code", "--json"])
    assert code == 1
    findings = json.loads(capsys.readouterr().out)
    assert any(f["rule"] == "aws-access-key" for f in findings)


def test_explicit_root_overrides_env(_isolate_home, monkeypatch):
    custom = _isolate_home / ".claude-personal"
    override = _isolate_home / "explicit"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(custom))
    src = ClaudeCodeSource(root=override)
    assert src.roots() == [override]


def test_fix_redacts_in_custom_profile(_isolate_home, monkeypatch):
    custom = _isolate_home / ".claude-personal"
    f = _seed_profile(custom)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(custom))

    code = main(["fix", "--source", "claude-code", "--force", "--allow-production"])
    assert code == 0
    assert AWS_KEY not in f.read_text(encoding="utf-8")
    assert f.with_name(f.name + ".bak").exists()


def test_is_detected_tracks_profiles(_isolate_home, monkeypatch):
    custom = _isolate_home / ".claude-personal"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(custom))
    assert ClaudeCodeSource().is_detected() is False
    _seed_profile(custom)
    assert ClaudeCodeSource().is_detected() is True
