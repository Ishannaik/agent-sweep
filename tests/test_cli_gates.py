from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.sources import ClaudeCodeSource  # noqa: E402
from agentsweep.preflight import is_production_root  # noqa: E402


def test_is_production_root_true_for_default(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    (fake_home / ".claude" / "projects").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    default_source = ClaudeCodeSource()
    assert is_production_root(default_source, ClaudeCodeSource)


def test_is_production_root_false_for_override(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    (fake_home / ".claude" / "projects").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    other = tmp_path / "other"
    other.mkdir()
    overridden = ClaudeCodeSource(root=other)
    assert not is_production_root(overridden, ClaudeCodeSource)


def test_cli_fix_refuses_default_root_without_allow_production(
    tmp_path, monkeypatch, capsys
):
    from agentsweep.cli import main

    fake_home = tmp_path / "home"
    fake_root = fake_home / ".claude" / "projects"
    fake_root.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    # Seed a scannable file so we reach the fix phase.
    session = fake_root / "session.jsonl"
    session.write_text(
        '{"type":"user","message":{"content":[{"type":"text","text":"key=AKIAIOSFODNN7EXAMPLE"}]}}\n',
        encoding="utf-8",
    )

    exit_code = main(["--fix"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "default production root" in captured.err
    assert "--allow-production" in captured.err
    assert session.read_text(encoding="utf-8").find("AKIAIOSFODNN7EXAMPLE") != -1
    assert not (fake_root / "session.jsonl.bak").exists()
