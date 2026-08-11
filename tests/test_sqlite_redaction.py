"""End-to-end redaction tests for the SQLite-backed sources (Cursor /
Windsurf *.vscdb, OpenCode opencode.db).

Regression coverage for the redact-without-backup bug: apply_redactions
used to UPDATE the production database in place and then hand a latin-1
passthrough of the (already mutated) file to safe_write, which always
failed its UTF-8/JSONL checks — the redaction had silently happened, but
the run reported FAIL, no .bak existed, no audit record was written, and
undo had nothing to restore. The fix makes apply_redactions side-effect
free (it rewrites a temp copy and returns bytes), so safe_write owns the
backup and the atomic replace for SQLite exactly as it does for JSONL.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.pipeline import _build_redactions, _scan_file, undo  # noqa: E402
from agentsweep.redactor import safe_write  # noqa: E402
from agentsweep.sources import CursorSource, OpenCodeSource  # noqa: E402

SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example access key id


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    # Keep the audit log (and Cursor's ~/.cursor transcript discovery)
    # away from the real home directory.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def _make_vscdb(db: Path) -> bytes:
    """Build a minimal Cursor-style state.vscdb with one secret embedded in
    a JSON blob (cursorDiskKV) and one as a bare column value (ItemTable),
    covering both UPDATE branches. Returns the original file bytes."""
    db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
    con.execute(
        "INSERT INTO cursorDiskKV VALUES (?, ?)",
        ("bubbleId:1", json.dumps({"text": f"my key is {SECRET} btw"})),
    )
    con.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO ItemTable VALUES (?, ?)", ("chat", f"plain {SECRET}"))
    con.commit()
    con.close()
    return db.read_bytes()


def _redact(source, f: Path):
    """Mirror the pipeline's scan -> redactions -> apply composition."""
    _, items, _, _, _ = _scan_file(source, f, ignores=None)
    assert items, "fixture secret should be detected"
    return source.apply_redactions(f, _build_redactions(items))


def test_cursor_fix_backs_up_original_and_redacts(tmp_path: Path) -> None:
    root = tmp_path / "User"
    db = root / "globalStorage" / "state.vscdb"
    original = _make_vscdb(db)
    source = CursorSource(root=root)
    assert db in source.files()

    new_content = _redact(source, db)

    # apply_redactions must be side-effect free on the production file...
    assert isinstance(new_content, bytes)
    assert db.read_bytes() == original

    record = safe_write(db, new_content, backup=True)

    # ...so the .bak written by safe_write is the true pre-redaction original.
    bak = db.with_name(db.name + ".bak")
    assert record.backup == bak
    assert bak.read_bytes() == original

    redacted = db.read_bytes()
    # Gone from live rows AND from freelist/slack space (secure_delete+VACUUM).
    assert SECRET.encode() not in redacted

    con = sqlite3.connect(db)
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    values = [r[0] for r in con.execute("SELECT value FROM cursorDiskKV")]
    values += [r[0] for r in con.execute("SELECT value FROM ItemTable")]
    con.close()
    assert all(SECRET not in v for v in values)
    assert sum("[REDACTED:" in v for v in values) == 2  # both branches hit
    # The JSON blob is still parseable JSON after the in-JSON patch.
    blob = json.loads(values[0])
    assert "[REDACTED:" in blob["text"]


def test_opencode_db_fix_backs_up_original_and_redacts(tmp_path: Path) -> None:
    root = tmp_path / "opencode"
    db = root / "opencode.db"
    db.parent.mkdir(parents=True)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE part (id TEXT, content TEXT)")
    con.execute(
        "INSERT INTO part VALUES (?, ?)",
        ("p1", json.dumps({"type": "text", "text": f"token {SECRET}"})),
    )
    con.commit()
    con.close()
    original = db.read_bytes()

    source = OpenCodeSource(root=root)
    assert source.files() == [db]

    new_content = _redact(source, db)
    assert isinstance(new_content, bytes)
    assert db.read_bytes() == original

    safe_write(db, new_content, backup=True)
    assert db.with_name(db.name + ".bak").read_bytes() == original
    assert SECRET.encode() not in db.read_bytes()
    con = sqlite3.connect(db)
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    con.close()


def test_undo_restores_vscdb_backup(tmp_path: Path) -> None:
    root = tmp_path / "User"
    db = root / "globalStorage" / "state.vscdb"
    original = _make_vscdb(db)
    source = CursorSource(root=root)
    safe_write(db, _redact(source, db), backup=True)
    assert db.read_bytes() != original

    code = undo(argparse.Namespace(source="cursor", root=root))
    assert code == 0
    assert db.read_bytes() == original
    assert not db.with_name(db.name + ".bak").exists()


def test_safe_write_bytes_skips_line_validation(tmp_path: Path) -> None:
    # bytes content is the binary-format contract: no JSONL/line-count
    # checks, no UTF-8 decode of the original.
    target = tmp_path / "state.vscdb"
    target.write_bytes(b"SQLite format 3\x00" + b"\xde\xad\xbe\xef" * 8)
    new = b"SQLite format 3\x00" + b"\x00" * 32
    record = safe_write(target, new, backup=False)
    assert target.read_bytes() == new
    assert record.backup is None
