"""A SQLite database in WAL mode keeps committed pages in `<db>-wal` until a
checkpoint folds them in. Redacting the database while that file survives is a
silent no-op: the plaintext stays on disk in the `-wal`, and SQLite replays it
over the replaced database on the next open.

These tests pin the whole contract — the secret leaves the disk, the redaction
survives the next open, no rows are lost, and `undo` still round-trips.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from agentsweep.redactor import safe_write
from agentsweep.sources._core import OpenCodeSource

SECRET = "sk-ant-api03-" + "A" * 40  # noqa: S105 — synthetic, matches no real key
REDACTED = "sk-ant-api03-REDACTED"

# Run in a child that exits via os._exit so SQLite never gets to checkpoint and
# delete the -wal on close. This is what an agent killed mid-session leaves.
_BUILDER = textwrap.dedent(
    """
    import json, os, sqlite3, sys
    con = sqlite3.connect(sys.argv[1])
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE part (id TEXT PRIMARY KEY, content TEXT)")
    for i in range(200):
        con.execute("INSERT INTO part VALUES (?,?)",
                    (f"pad{i}", json.dumps({"type": "text", "text": "x" * 400})))
    con.commit()
    con.execute("INSERT INTO part VALUES (?,?)",
                ("secret-row", json.dumps({"type": "text", "text": sys.argv[2]})))
    con.commit()
    os._exit(0)
    """
)


@pytest.fixture()
def wal_db(tmp_path: Path) -> Path:
    """An opencode.db whose rows live only in an uncheckpointed -wal."""
    db = tmp_path / "opencode.db"
    subprocess.run([sys.executable, "-c", _BUILDER, str(db), SECRET], check=True)
    assert (tmp_path / "opencode.db-wal").is_file(), "fixture must leave a -wal"
    assert SECRET.encode() in (tmp_path / "opencode.db-wal").read_bytes()
    assert SECRET.encode() not in db.read_bytes(), "secret must live only in the -wal"
    return db


def _redact(db: Path, *, backup: bool = True):
    source = OpenCodeSource(root=db.parent)
    hits = [(ln, kp, v) for ln, kp, v in source.iter_strings(db) if SECRET in v]
    assert len(hits) == 1, f"scan should find the secret through the WAL, got {hits}"
    ln, kp, val = hits[0]
    new_bytes = source.apply_redactions(db, [(ln, kp, val.replace(SECRET, REDACTED))])
    return safe_write(
        db,
        new_bytes,
        backup=backup,
        fmt=source.content_format(db),
        sidecars=source.sidecars(db),
    )


def test_sidecars_are_reported_for_the_database(wal_db: Path) -> None:
    names = {p.name for p in OpenCodeSource(root=wal_db.parent).sidecars(wal_db)}
    assert names == {"opencode.db-wal", "opencode.db-shm"}


def test_sidecars_are_empty_for_non_sqlite_paths(tmp_path: Path) -> None:
    stray = tmp_path / "storage" / "session.json"
    stray.parent.mkdir()
    stray.write_text("{}")
    assert OpenCodeSource(root=tmp_path).sidecars(stray) == []


def test_redaction_removes_the_wal_and_survives_reopen(wal_db: Path) -> None:
    _redact(wal_db)

    assert not (wal_db.parent / "opencode.db-wal").exists(), (
        "stale -wal must be retired"
    )
    assert not (wal_db.parent / "opencode.db-shm").exists(), (
        "stale -shm must be retired"
    )
    assert SECRET.encode() not in wal_db.read_bytes()

    # The next open is where the old code lost: WAL recovery replayed the
    # pre-redaction pages straight back over the redacted database.
    con = sqlite3.connect(str(wal_db))
    try:
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert con.execute("SELECT count(*) FROM part").fetchone()[0] == 201
        (content,) = con.execute(
            "SELECT content FROM part WHERE id='secret-row'"
        ).fetchone()
    finally:
        con.close()
    assert SECRET not in content
    assert json.loads(content)["text"] == REDACTED


def test_no_plaintext_secret_left_anywhere_beside_the_database(wal_db: Path) -> None:
    _redact(wal_db, backup=False)
    for leftover in wal_db.parent.iterdir():
        assert SECRET.encode() not in leftover.read_bytes(), (
            f"secret survived in {leftover.name}"
        )


def test_sidecars_are_backed_up_and_undo_round_trips(wal_db: Path) -> None:
    d = wal_db.parent
    _redact(wal_db)

    wal_bak = d / "opencode.db-wal.bak"
    assert (d / "opencode.db.bak").is_file()
    assert wal_bak.is_file(), "the -wal held plaintext; it must be recoverable"

    # undo: restore every .bak over its original (what pipeline.undo does).
    for bak in sorted(d.glob("*.bak")):
        os.replace(bak, bak.with_name(bak.name[: -len(".bak")]))

    con = sqlite3.connect(str(wal_db))
    try:
        (content,) = con.execute(
            "SELECT content FROM part WHERE id='secret-row'"
        ).fetchone()
    finally:
        con.close()
    assert json.loads(content)["text"] == SECRET, "undo must restore the original rows"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits are not meaningful on Windows",
)
def test_sidecar_backup_is_owner_only(wal_db: Path) -> None:
    """A `-wal` backup holds the same plaintext the `.bak` does."""
    old_umask = os.umask(0o000)
    try:
        _redact(wal_db)
    finally:
        os.umask(old_umask)
    mode = stat.S_IMODE((wal_db.parent / "opencode.db-wal.bak").stat().st_mode)
    assert mode == 0o600, f"sidecar backup mode is {oct(mode)}, expected 0o600"


def test_pipeline_redaction_is_not_undone_by_wal_replay(
    wal_db: Path, monkeypatch
) -> None:
    """The end-to-end guard, driving `_redact_all` — the real `fix` caller.

    Before the sidecar fix this test failed on behaviour, not on a missing
    attribute: `_redact_all` replaced opencode.db, left the `-wal` beside it,
    and the very next connect() replayed the pre-redaction pages back.
    """
    import agentsweep.pipeline as pipeline
    from agentsweep import ignore as ignore_mod

    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))
    past = time.time() - 9999
    for p in sorted(wal_db.parent.iterdir()):
        os.utime(p, (past, past))

    source = OpenCodeSource(root=wal_db.parent)
    found_by_file, *_ = pipeline._scan(source, source.files(), ignore_mod.IgnoreSet())
    assert found_by_file, "the scanner must see the secret through the WAL"

    rows, errors, _ = pipeline._redact_all(
        source, found_by_file, backup=True, force=False
    )
    assert errors == 0, f"redaction reported errors: {rows}"

    con = sqlite3.connect(str(wal_db))
    try:
        (content,) = con.execute(
            "SELECT content FROM part WHERE id='secret-row'"
        ).fetchone()
    finally:
        con.close()
    assert SECRET not in content, "WAL replay resurrected the redacted secret"


def test_failed_write_leaves_sidecars_and_their_backups_alone(
    wal_db: Path, monkeypatch
) -> None:
    d = wal_db.parent
    before = (d / "opencode.db-wal").read_bytes()

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        _redact(wal_db)

    assert (d / "opencode.db-wal").read_bytes() == before, (
        "-wal must survive a failed write"
    )
    assert not (d / "opencode.db-wal.bak").exists(), (
        "aborted write must clean its backups"
    )
    assert not (d / "opencode.db.bak").exists()
