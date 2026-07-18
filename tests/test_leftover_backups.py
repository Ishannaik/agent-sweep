"""scan warns about leftover .bak sidecars that still hold plaintext secrets.

After `fix` writes `<path>.bak` and before `purge` deletes it, the secret is
still on disk. A scan of the redacted files finds nothing, so without this
warning the user reads an all-clear over a live secret.
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

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
_CLEAN = '{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}\n'
_SECRET = (
    '{"type":"user","message":{"content":'
    '[{"type":"text","text":"key=AKIAIOSFODNN7EXAMPLE"}]}}\n'
)
_WARN = "leftover .bak"


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg" / "config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("AGENTSWEEP_NO_UPDATE", "1")
    return home


@pytest.fixture(autouse=True)
def _no_agent_running(monkeypatch):
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))


def _mk_root(base: Path, *, clean: bool = True, bak: bool = False) -> Path:
    root = base / "projects"
    d = root / "proj"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "session.jsonl"
    f.write_text(_CLEAN if clean else _SECRET, encoding="utf-8")
    past = time.time() - 3700
    os.utime(f, (past, past))
    if bak:
        (d / "session.jsonl.bak").write_text(_SECRET, encoding="utf-8")
    return root


def test_warning_text_and_count_human(tmp_path, capsys):
    root = _mk_root(tmp_path, clean=True, bak=True)
    code = main(["scan", "--source", "claude-code", "--root", str(root)])
    # warn_line writes to stderr (keeps stdout clean); assert on it.
    err = capsys.readouterr().err
    assert code == 0
    assert _WARN in err
    assert "1 leftover" in err
    assert "purge" in err


def test_warns_on_stderr_in_json_mode(tmp_path, capsys):
    root = _mk_root(tmp_path, clean=True, bak=True)
    code = main(["scan", "--source", "claude-code", "--root", str(root), "--json"])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out) == []      # stdout stays parseable
    assert _WARN in captured.err               # warning goes to stderr


def test_no_warning_without_bak(tmp_path, capsys):
    root = _mk_root(tmp_path, clean=False, bak=False)
    code = main(["scan", "--source", "claude-code", "--root", str(root)])
    captured = capsys.readouterr()
    assert code == 1          # the live secret is still found
    assert _WARN not in (captured.out + captured.err)


def test_warns_even_when_findings_present(tmp_path, capsys):
    # Both a live secret in the file AND a leftover .bak — warn about both.
    root = _mk_root(tmp_path, clean=False, bak=True)
    code = main(["scan", "--source", "claude-code", "--root", str(root)])
    err = capsys.readouterr().err
    assert code == 1
    assert _WARN in err


def test_bak_contents_not_leaked_to_output(tmp_path, capsys):
    root = _mk_root(tmp_path, clean=True, bak=True)
    main(["scan", "--source", "claude-code", "--root", str(root)])
    captured = capsys.readouterr()
    # The warning reports existence + count, never the secret inside the .bak.
    assert AWS_KEY not in captured.out
    assert AWS_KEY not in captured.err


def test_scan_all_warns_about_backups(tmp_path, capsys):
    # scan --all is what the pre-commit hook runs, so it must warn too.
    home = tmp_path / "home"
    d = home / ".claude" / "projects" / "proj"
    d.mkdir(parents=True)
    f = d / "session.jsonl"
    f.write_text(_CLEAN, encoding="utf-8")
    past = time.time() - 3700
    os.utime(f, (past, past))
    (d / "session.jsonl.bak").write_text(_SECRET, encoding="utf-8")

    code = main(["scan", "--all", "--json"])
    captured = capsys.readouterr()
    assert code == 0
    assert _WARN in captured.err


def test_leftover_backups_helper_counts_all_glob_types(tmp_path):
    from agentsweep.pipeline import _leftover_backups
    from agentsweep.sources import ClaudeCodeSource

    root = tmp_path / "projects"
    d = root / "proj"
    d.mkdir(parents=True)
    (d / "a.jsonl.bak").write_text("x", encoding="utf-8")
    (d / "b.db.bak").write_text("x", encoding="utf-8")
    (d / "c.jsonl").write_text("x", encoding="utf-8")  # not a backup

    found = _leftover_backups(ClaudeCodeSource(root=root))
    assert len(found) == 2
