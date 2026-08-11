"""Crush source: per-project db discovery, scanning, and redaction round-trip.

Crush keeps no central history: each project it runs in gets its own
<project>/.crush/crush.db, so discovery walks from home like Aider rather than
reading one platform path.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline  # noqa: E402
from agentsweep.cli import main  # noqa: E402
from agentsweep.sources import SOURCES, CrushSource  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# Crush's schema, from internal/db/migrations/20250424200609_initial.sql.
_SCHEMA = """
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    parent_session_id TEXT,
    title TEXT NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    cost REAL NOT NULL DEFAULT 0.0,
    updated_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    parts TEXT NOT NULL DEFAULT '[]',
    model TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    finished_at INTEGER
);
CREATE TABLE files (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    path TEXT NOT NULL,
    content TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture(autouse=True)
def _no_agent_running(monkeypatch):
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))


def _mk_crush_db(project: Path, *, age_seconds: int = 3700) -> Path:
    """Create <project>/.crush/crush.db holding a secret in parts and content."""
    data_dir = project / ".crush"
    data_dir.mkdir(parents=True, exist_ok=True)
    db = data_dir / "crush.db"
    con = sqlite3.connect(db)
    try:
        con.executescript(_SCHEMA)
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?)",
            ("s1", None, "deploy help", 2, 10, 20, 0.01, 1, 1),
        )
        con.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)",
            (
                "m1",
                "s1",
                "user",
                json.dumps([{"type": "text", "text": f"my key is {AWS_KEY}"}]),
                "claude",
                1,
                1,
                1,
            ),
        )
        con.execute(
            "INSERT INTO files VALUES (?,?,?,?,?,?,?)",
            ("f1", "s1", ".env", f"GITHUB_TOKEN={GH_TOKEN}\n", 0, 1, 1),
        )
        con.commit()
    finally:
        con.close()
    past = time.time() - age_seconds
    os.utime(db, (past, past))
    return db


def test_registered_in_sources():
    assert SOURCES["crush"] is CrushSource


def test_default_root_is_home(_isolate_home):
    assert CrushSource().root == Path.home()


def test_discovers_per_project_db(tmp_path):
    project = tmp_path / "work" / "myrepo"
    project.mkdir(parents=True)
    db = _mk_crush_db(project)
    assert CrushSource(root=tmp_path).files() == [db]


def test_discovers_multiple_projects(tmp_path):
    a = tmp_path / "repo_a"
    b = tmp_path / "nested" / "repo_b"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    _mk_crush_db(a)
    _mk_crush_db(b)
    assert len(CrushSource(root=tmp_path).files()) == 2


def test_skips_pruned_dirs(tmp_path):
    buried = tmp_path / "node_modules" / "pkg"
    buried.mkdir(parents=True)
    _mk_crush_db(buried)
    assert CrushSource(root=tmp_path).files() == []


def test_data_dir_without_db_is_ignored(tmp_path):
    (tmp_path / "proj" / ".crush").mkdir(parents=True)
    assert CrushSource(root=tmp_path).files() == []


def test_is_detected_tracks_real_history(tmp_path, _isolate_home):
    assert CrushSource(root=tmp_path).is_detected() is False
    _mk_crush_db(tmp_path / "proj")
    assert CrushSource(root=tmp_path).is_detected() is True


def test_iter_strings_finds_secret(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    db = _mk_crush_db(project)
    values = [v for _, _, v in CrushSource(root=tmp_path).iter_strings(db)]
    assert any(AWS_KEY in v for v in values)
    assert any(GH_TOKEN in v for v in values)


def test_scan_finds_secret(tmp_path, capsys):
    project = tmp_path / "proj"
    project.mkdir()
    _mk_crush_db(project)
    code = main(["scan", "--source", "crush", "--root", str(tmp_path), "--json"])
    assert code == 1
    findings = json.loads(capsys.readouterr().out)
    assert any(f["rule"] == "aws-access-key" for f in findings)


def test_fix_redacts_and_db_stays_valid(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    db = _mk_crush_db(project)

    code = main(
        [
            "fix",
            "--source",
            "crush",
            "--root",
            str(tmp_path),
            "--force",
            "--allow-production",
        ]
    )
    assert code == 0

    con = sqlite3.connect(db)
    try:
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        parts = con.execute("SELECT parts FROM messages WHERE id='m1'").fetchone()[0]
        content = con.execute("SELECT content FROM files WHERE id='f1'").fetchone()[0]
    finally:
        con.close()

    assert AWS_KEY not in parts
    assert "[REDACTED:aws-access-key]" in parts
    assert json.loads(parts)[0]["type"] == "text"
    assert GH_TOKEN not in content
    assert db.with_name(db.name + ".bak").exists()


def test_undo_restores_db(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    db = _mk_crush_db(project)
    original = db.read_bytes()

    assert (
        main(
            [
                "fix",
                "--source",
                "crush",
                "--root",
                str(tmp_path),
                "--force",
                "--allow-production",
            ]
        )
        == 0
    )
    assert main(["undo", "--source", "crush", "--root", str(tmp_path)]) == 0
    assert db.read_bytes() == original
