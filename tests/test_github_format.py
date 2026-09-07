"""GitHub Actions annotation output shape, safety, and CLI contracts."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import main  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("AGENTSWEEP_NO_UPDATE", "1")
    return home


def _seed(base: Path, *secrets: str) -> Path:
    root = base / "scan_root"
    root.mkdir(parents=True, exist_ok=True)
    history = root / "session.jsonl"
    history.write_text(
        "".join(
            '{"type":"user","message":{"content":[{"type":"text",'
            f'"text":"key={secret}"}}]}}}}\n'
            for secret in secrets
        ),
        encoding="utf-8",
    )
    past = time.time() - 3700
    os.utime(history, (past, past))
    return root


def test_annotation_shape_and_masking(tmp_path, capsys):
    root = _seed(tmp_path, AWS_KEY, GH_TOKEN)

    code = main(["scan", "--root", str(root), "--format", "github"])
    captured = capsys.readouterr()
    lines = captured.out.splitlines()

    assert code == 1
    assert len(lines) == 2
    assert all(line.startswith("::error file=") for line in lines)
    assert ",line=1::" in lines[0]
    assert ",line=2::" in lines[1]
    assert "AWS access key found in claude-code history" in captured.out
    assert AWS_KEY not in captured.out
    assert GH_TOKEN not in captured.out
    assert "AKIAIO" in captured.out
    assert captured.err == ""


def test_clean_scan_emits_nothing(tmp_path, capsys):
    root = _seed(tmp_path)

    code = main(["scan", "--root", str(root), "--format", "github"])
    captured = capsys.readouterr()

    assert code == 0
    assert captured.out == ""


def test_output_file_keeps_stdout_clean(tmp_path, capsys):
    root = _seed(tmp_path, AWS_KEY)
    output = tmp_path / "annotations.txt"

    code = main(["scan", "--root", str(root), "--format", "github", "-o", str(output)])
    captured = capsys.readouterr()

    assert code == 1
    assert captured.out == ""
    assert output.read_text(encoding="utf-8").startswith("::error file=")
    assert AWS_KEY not in output.read_text(encoding="utf-8")


@pytest.mark.parametrize("secrets", [(), (AWS_KEY,)])
def test_output_write_failure_is_user_error(tmp_path, capsys, secrets):
    root = _seed(tmp_path, *secrets)
    output = tmp_path / "output-directory"
    output.mkdir()

    code = main(["scan", "--root", str(root), "--format", "github", "-o", str(output)])
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert f"Could not write {output}" in captured.err
    assert "finding(s) written" not in captured.err


def test_all_sources_uses_same_annotation_format(_isolate_home, capsys):
    root = _isolate_home / ".claude" / "projects"
    root.mkdir(parents=True)
    history = root / "session.jsonl"
    history.write_text(
        '{"type":"user","message":{"content":[{"type":"text",'
        f'"text":"key={AWS_KEY}"}}]}}}}\n',
        encoding="utf-8",
    )

    code = main(["scan", "--all", "--detected", "--format", "github"])
    captured = capsys.readouterr()

    assert code == 1
    assert captured.out.startswith("::error file=")
    assert "found in claude-code history" in captured.out
    assert AWS_KEY not in captured.out


def test_missing_root_is_user_error_with_clean_stdout(tmp_path, capsys):
    code = main(["scan", "--root", str(tmp_path / "missing"), "--format", "github"])
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "Path not found" in captured.err


def test_github_format_rejects_json_and_fix(tmp_path):
    with pytest.raises(SystemExit):
        main(["scan", "--root", str(tmp_path), "--format", "github", "--json"])
    with pytest.raises(SystemExit):
        main(["fix", "--root", str(tmp_path), "--format", "github"])
