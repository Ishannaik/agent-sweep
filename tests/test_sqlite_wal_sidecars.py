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

import agentsweep.redactor as redactor
from agentsweep.redactor import (
    RedactionTarget,
    RedactionVerification,
    safe_write,
)
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
    """Apply one verified synthetic-secret replacement to the WAL database."""
    source = OpenCodeSource(root=db.parent)
    hits = [(ln, kp, v) for ln, kp, v in source.iter_strings(db) if SECRET in v]
    assert len(hits) == 1, f"scan should find the secret through the WAL, got {hits}"
    ln, kp, val = hits[0]
    replacement = val.replace(SECRET, REDACTED)
    return safe_write(
        db,
        source.apply_redactions(db, [(ln, kp, replacement)]),
        backup=backup,
        fmt=source.content_format(db),
        sidecars=source.sidecars(db),
        verification=RedactionVerification(
            source=source,
            targets=(
                RedactionTarget(
                    line=ln,
                    keypath=tuple(kp),
                    original=val,
                    replacement=replacement,
                    rule="anthropic",
                    span=(val.index(SECRET), val.index(SECRET) + len(SECRET)),
                ),
            ),
        ),
    )


def _block_main_recovery_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the verified no-backup cleanup branch without changing permissions."""
    real_unlink = Path.unlink

    def fail_main_recovery_unlink(path: Path, *args, **kwargs) -> None:
        """Fail only removal of the database's prepared recovery copy."""
        if path.suffix == ".recover" and path.name.startswith(".opencode.db."):
            raise OSError("synthetic main recovery cleanup failure")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_main_recovery_unlink)


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


def test_recovery_cleanup_failure_restores_wal_only_rows_without_audit(
    wal_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed main recovery cleanup restores the database and both sidecars."""
    audit = wal_db.parent / "audit.jsonl"
    monkeypatch.setattr(redactor, "audit_path", lambda: audit)
    _block_main_recovery_cleanup(monkeypatch)

    with pytest.raises(redactor.SafetyError, match="was rolled back"):
        _redact(wal_db, backup=False)

    assert not audit.exists(), "a rolled-back write must not report success"
    assert (wal_db.parent / "opencode.db-wal").is_file()
    assert (wal_db.parent / "opencode.db-shm").is_file()
    con = sqlite3.connect(str(wal_db))
    try:
        assert con.execute("SELECT count(*) FROM part").fetchone()[0] == 201
        (content,) = con.execute(
            "SELECT content FROM part WHERE id='secret-row'"
        ).fetchone()
    finally:
        con.close()
    assert json.loads(content)["text"] == SECRET


def test_recovery_rollback_reports_every_retained_sidecar_copy(
    wal_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failed restores retain and enumerate every prepared main and sidecar copy."""
    audit = wal_db.parent / "audit.jsonl"
    sidecars = (
        wal_db.with_name("opencode.db-wal"),
        wal_db.with_name("opencode.db-shm"),
    )
    originals = {
        wal_db: wal_db.read_bytes(),
        sidecars[0]: sidecars[0].read_bytes(),
    }
    recovery_sources = (wal_db, *sidecars)
    real_replace = os.replace
    restored_targets: set[str] = set()

    def fail_prepared_recoveries(src, dst, *args, **kwargs) -> None:
        """Leave every prepared recovery in place while recording each restore."""
        if Path(src).suffix == ".recover":
            restored_targets.add(Path(dst).name)
            raise OSError("synthetic prepared recovery restore failure")
        real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(redactor, "audit_path", lambda: audit)
    monkeypatch.setattr(redactor.os, "replace", fail_prepared_recoveries)
    _block_main_recovery_cleanup(monkeypatch)

    with pytest.raises(redactor.SafetyError, match="rollback was incomplete") as exc:
        _redact(wal_db, backup=False)

    message = str(exc.value)
    assert restored_targets == {path.name for path in recovery_sources}
    recoveries: dict[Path, Path] = {}
    for original in recovery_sources:
        paths = list(wal_db.parent.glob(f".{original.name}.*.recover"))
        assert len(paths) == 1
        recoveries[original] = paths[0]
        assert str(paths[0]) in message
    for original, bytes_before in originals.items():
        assert recoveries[original].read_bytes() == bytes_before

    recovered = wal_db.with_name("recovered.db")
    for original, recovery in recoveries.items():
        suffix = original.name.removeprefix(wal_db.name)
        target = recovered.with_name(f"{recovered.name}{suffix}")
        target.write_bytes(recovery.read_bytes())
    con = sqlite3.connect(str(recovered))
    try:
        assert con.execute("SELECT count(*) FROM part").fetchone()[0] == 201
        (content,) = con.execute(
            "SELECT content FROM part WHERE id='secret-row'"
        ).fetchone()
    finally:
        con.close()
    assert json.loads(content)["text"] == SECRET
    assert "was rolled back" not in message
    assert not audit.exists(), "an incomplete rollback must not report success"
