"""Current opencode stores message content in `part.data` / `message.data`
(drizzle schema); the old whitelist only knew the legacy `part.content` /
`message.metadata` columns and a blanket OperationalError swallow hid the
"no such column" — so a scan touched only `session.title` and reported a
false all-clear (issue #14).

These tests pin the fix: the current schema is actually scanned, the legacy
schema still works, and an unrecognised schema raises loudly instead of
silently returning clean.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agentsweep.pipeline import _scan_file
from agentsweep.sources._core import OpenCodeSource

SECRET = "sk-ant-api03-" + "A" * 40  # noqa: S105 — synthetic, matches no real key


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    # Keep audit-log and default-root resolution away from the real home.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def _make_current_schema_db(root: Path) -> Path:
    """A minimal opencode.db shaped like today's drizzle schema: JSON in
    `part.data` / `message.data`, no `content` / `metadata` columns."""
    root.mkdir(parents=True, exist_ok=True)
    db = root / "opencode.db"
    con = sqlite3.connect(db)
    try:
        con.execute(
            "CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, "
            "session_id TEXT, data TEXT)"
        )
        con.execute(
            "CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT)"
        )
        con.execute("CREATE TABLE session (id TEXT PRIMARY KEY, title TEXT)")
        con.execute(
            "INSERT INTO part VALUES (?,?,?,?)",
            (
                "prt_1",
                "msg_1",
                "ses_1",
                json.dumps({"type": "text", "text": f"my key is {SECRET} btw"}),
            ),
        )
        con.execute(
            "INSERT INTO message VALUES (?,?,?)",
            ("msg_1", "ses_1", json.dumps({"role": "user"})),
        )
        con.execute("INSERT INTO session VALUES (?,?)", ("ses_1", "a session"))
        con.commit()
    finally:
        con.close()
    return db


def test_current_schema_part_data_is_scanned(tmp_path: Path) -> None:
    """The regression of issue #14: on the current schema the secret lives in
    `part.data`, which the old whitelist never selected — the scan saw only
    `session.title` and reported CLEAN."""
    db = _make_current_schema_db(tmp_path / "opencode")
    source = OpenCodeSource(root=db.parent)

    hits = [(ln, kp, v) for ln, kp, v in source.iter_strings(db) if SECRET in v]
    assert hits, "secret in part.data must be surfaced, not a false all-clear"
    (_ln, kp, _v) = hits[0]
    assert kp[:3] == ["part", 1, "data"], f"unexpected keypath {kp}"

    # And through the real pipeline scanner, as a detection.
    _, items, strings_scanned, _, _ = _scan_file(source, db, ignores=None)
    assert strings_scanned > 1, "scan must not be reduced to session.title"
    assert any(f.rule == "anthropic" for _l, _k, _v, f in items)


def test_current_schema_message_data_is_scanned(tmp_path: Path) -> None:
    db = _make_current_schema_db(tmp_path / "opencode")
    con = sqlite3.connect(db)
    try:
        con.execute(
            "UPDATE message SET data = ? WHERE id = 'msg_1'",
            (json.dumps({"role": "user", "note": SECRET}),),
        )
        con.commit()
    finally:
        con.close()

    source = OpenCodeSource(root=db.parent)
    hits = [kp for _ln, kp, v in source.iter_strings(db) if SECRET in v]
    assert any(kp[:3] == ["message", 1, "data"] for kp in hits)


def test_legacy_schema_content_column_still_scanned(tmp_path: Path) -> None:
    """Old opencode installs keep `part.content` — the legacy candidate must
    survive the whitelist update."""
    root = tmp_path / "opencode"
    root.mkdir(parents=True)
    db = root / "opencode.db"
    con = sqlite3.connect(db)
    try:
        con.execute("CREATE TABLE part (id TEXT PRIMARY KEY, content TEXT)")
        con.execute(
            "INSERT INTO part VALUES (?,?)",
            ("p1", json.dumps({"type": "text", "text": SECRET})),
        )
        con.commit()
    finally:
        con.close()

    source = OpenCodeSource(root=root)
    hits = [kp for _ln, kp, v in source.iter_strings(db) if SECRET in v]
    assert any(kp[:3] == ["part", 1, "content"] for kp in hits)


def test_whitelist_intersects_with_real_columns(tmp_path: Path) -> None:
    """Dead candidates (e.g. `part.content` on a current db) must not be
    returned — selecting them is what the old blanket swallow papered over."""
    db = _make_current_schema_db(tmp_path / "opencode")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        pairs = OpenCodeSource(root=db.parent)._sqlite_text_columns(con)
    finally:
        con.close()
    assert set(pairs) == {("part", "data"), ("message", "data"), ("session", "title")}


def test_schema_drift_raises_instead_of_clean(tmp_path: Path) -> None:
    """A known table with NONE of its candidate text columns means the schema
    moved again. That must be loud — a secret scanner's worst failure mode is
    a silent false all-clear."""
    root = tmp_path / "opencode"
    root.mkdir(parents=True)
    db = root / "opencode.db"
    con = sqlite3.connect(db)
    try:
        con.execute("CREATE TABLE part (id TEXT PRIMARY KEY)")  # no text col
        con.execute("INSERT INTO part VALUES ('p1')")
        con.commit()
    finally:
        con.close()

    source = OpenCodeSource(root=root)
    with pytest.raises(RuntimeError, match="OpenCode schema drift"):
        list(source.iter_strings(db))


def test_missing_table_is_fine_not_drift(tmp_path: Path) -> None:
    """A whitelisted table simply not existing is not drift — e.g. a fresh db
    with only `session` must scan without raising."""
    root = tmp_path / "opencode"
    root.mkdir(parents=True)
    db = root / "opencode.db"
    con = sqlite3.connect(db)
    try:
        con.execute("CREATE TABLE session (id TEXT PRIMARY KEY, title TEXT)")
        con.execute("INSERT INTO session VALUES ('s1', 'hello')")
        con.commit()
    finally:
        con.close()

    source = OpenCodeSource(root=root)
    rows = list(source.iter_strings(db))
    assert rows == [(1, ["session", 1, "title"], "hello")]
