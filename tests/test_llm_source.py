"""End-to-end tests for the Datasette `llm` CLI source (simonw/llm).

`llm` logs every prompt/response to a single SQLite file, logs.db, and keeps
an FTS5 *external-content* full-text index (responses_fts) in sync with the
responses table via AFTER INSERT/UPDATE/DELETE triggers. The fixture below
reproduces that shape (the real column names, the FTS table, and the three
triggers) so the tests exercise the two things that actually matter:

  1. we scan the free-text columns a user pastes secrets into — and NOT the
     parallel *_json columns, which only duplicate that text; and
  2. redaction removes the secret from the FTS index too. Because the UPDATE
     fires responses_au, and _redact_sqlite_copy runs with secure_delete + a
     final VACUUM, no plaintext token survives in the FTS shadow tables.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.pipeline import _build_redactions, _scan_file, undo  # noqa: E402
from agentsweep.redactor import safe_write  # noqa: E402
from agentsweep.sources import SOURCES, LlmSource  # noqa: E402

# Five distinct, valid AWS access-key IDs (AKIA + 16 [0-9A-Z]).
KEY_PROMPT = "AKIAIOSFODNN7EXAMPLE"
KEY_SYSTEM = "AKIA1234567890ABCDEF"
KEY_RESPONSE = "AKIAFEDCBA0987654321"
KEY_FRAGMENT = "AKIAABCDEFGHIJKLMNOP"
KEY_CONVNAME = "AKIAQRSTUVWXYZ012345"
# Only ever written into responses.prompt_json — a column we deliberately do
# NOT scan (in real llm its text also lives in responses.prompt).
KEY_JSON_ONLY = "AKIA9NEVER8SCANNED70"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    # Keep safe_write's audit log (~/.agentsweep/audit.jsonl) out of real $HOME.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def _make_logs_db(db: Path) -> bytes:
    """Build a faithful (subset) llm logs.db and return its original bytes."""
    db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db)
    con.executescript(
        """
        CREATE TABLE conversations (id TEXT PRIMARY KEY, name TEXT, model TEXT);
        CREATE TABLE fragments (
            id INTEGER PRIMARY KEY, hash TEXT, content TEXT,
            datetime_utc TEXT, source TEXT
        );
        CREATE TABLE responses (
            id TEXT PRIMARY KEY, model TEXT, prompt TEXT, system TEXT,
            prompt_json TEXT, options_json TEXT, response TEXT,
            response_json TEXT, conversation_id TEXT
        );
        CREATE VIRTUAL TABLE responses_fts USING FTS5 (
            "prompt", "response", content="responses"
        );
        CREATE TRIGGER responses_ai AFTER INSERT ON responses BEGIN
          INSERT INTO responses_fts (rowid, "prompt", "response")
          VALUES (new.rowid, new."prompt", new."response");
        END;
        CREATE TRIGGER responses_ad AFTER DELETE ON responses BEGIN
          INSERT INTO responses_fts (responses_fts, rowid, "prompt", "response")
          VALUES('delete', old.rowid, old."prompt", old."response");
        END;
        CREATE TRIGGER responses_au AFTER UPDATE ON responses BEGIN
          INSERT INTO responses_fts (responses_fts, rowid, "prompt", "response")
          VALUES('delete', old.rowid, old."prompt", old."response");
          INSERT INTO responses_fts (rowid, "prompt", "response")
          VALUES (new.rowid, new."prompt", new."response");
        END;
        """
    )
    con.execute(
        "INSERT INTO conversations VALUES (?, ?, ?)",
        ("c1", f"fix {KEY_CONVNAME} creds", "gpt-4o"),
    )
    con.execute(
        "INSERT INTO fragments (id, hash, content) VALUES (?, ?, ?)",
        (1, "deadbeef", f"AWS_ACCESS_KEY_ID={KEY_FRAGMENT}\n"),
    )
    con.execute(
        "INSERT INTO responses (id, prompt, system, prompt_json, response, "
        "response_json, conversation_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "r1",
            f"deploy using {KEY_PROMPT} please",
            f"the operator key is {KEY_SYSTEM}",
            # prompt_json holds a secret we must NOT surface (dup-noise column).
            f'{{"messages": [{{"content": "token {KEY_JSON_ONLY}"}}]}}',
            f"sure, here it is: {KEY_RESPONSE}",
            '{"content": "r:r1"}',  # llm condenses response text to a placeholder
            "c1",
        ),
    )
    con.commit()
    con.close()
    return db.read_bytes()


def _redact(source: LlmSource, f: Path):
    """Mirror the pipeline's scan -> redactions -> apply composition."""
    _, items, _, _, _ = _scan_file(source, f, ignores=None)
    assert items, "fixture secrets should be detected"
    return source.apply_redactions(f, _build_redactions(items))


def test_llm_registered_and_stable() -> None:
    assert SOURCES["llm"] is LlmSource
    assert not LlmSource.experimental, "verified source must not be experimental"


def test_llm_default_root_honours_override(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LLM_USER_PATH", str(tmp_path / "llmdir"))
    src = LlmSource()
    assert src.root == tmp_path / "llmdir"
    assert src._db() == tmp_path / "llmdir" / "logs.db"
    # No logs.db yet -> nothing to scan and not "detected".
    assert src.files() == []
    assert src.is_detected() is False


def test_llm_iter_strings_finds_secret(tmp_path: Path) -> None:
    db = tmp_path / "io.datasette.llm" / "logs.db"
    _make_logs_db(db)
    source = LlmSource(root=db.parent)
    assert source.files() == [db]
    assert source.is_detected() is True

    _, items, _, _, _ = _scan_file(source, db, ignores=None)
    found = {fd.value for *_rest, fd in items}
    cols = {kp[2] for _ln, kp, _val, _fd in items}

    # Every free-text column secret is found...
    assert {KEY_PROMPT, KEY_SYSTEM, KEY_RESPONSE, KEY_FRAGMENT, KEY_CONVNAME} <= found
    # ...across exactly the whitelisted columns...
    assert cols == {"prompt", "system", "response", "content", "name"}
    # ...and the *_json duplicate-noise columns are never scanned.
    assert KEY_JSON_ONLY not in found
    assert "prompt_json" not in cols


def test_llm_redactions_preserve_structure_and_scrub_fts(tmp_path: Path) -> None:
    db = tmp_path / "io.datasette.llm" / "logs.db"
    original = _make_logs_db(db)
    source = LlmSource(root=db.parent)

    # Sanity: the FTS index really does hold the prompt/response tokens first.
    con = sqlite3.connect(db)
    assert con.execute(
        "SELECT count(*) FROM responses_fts WHERE responses_fts MATCH ?",
        (KEY_PROMPT.lower(),),
    ).fetchone()[0] == 1
    con.close()

    new_content = _redact(source, db)

    # apply_redactions is side-effect free: production db untouched, bytes back.
    assert isinstance(new_content, bytes)
    assert db.read_bytes() == original

    record = safe_write(
        db, new_content, backup=True,
        fmt=source.content_format(db), sidecars=source.sidecars(db),
    )
    assert record.backup == db.with_name(db.name + ".bak")
    assert record.backup.read_bytes() == original  # .bak is the true original

    redacted = db.read_bytes()
    for key in (KEY_PROMPT, KEY_SYSTEM, KEY_RESPONSE, KEY_FRAGMENT, KEY_CONVNAME):
        assert key.encode() not in redacted, f"{key} survived in the db file"

    con = sqlite3.connect(db)
    try:
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        # The secret is gone from every scanned column, replaced with a marker.
        prompt, system, response = con.execute(
            "SELECT prompt, system, response FROM responses WHERE id='r1'"
        ).fetchone()
        assert all("[REDACTED:" in v for v in (prompt, system, response))
        assert KEY_PROMPT not in prompt and KEY_RESPONSE not in response
        frag = con.execute("SELECT content FROM fragments WHERE id=1").fetchone()[0]
        name = con.execute("SELECT name FROM conversations WHERE id='c1'").fetchone()[0]
        assert "[REDACTED:" in frag and "[REDACTED:" in name
        # The FTS index no longer matches the redacted prompt/response tokens.
        for key in (KEY_PROMPT, KEY_RESPONSE):
            assert con.execute(
                "SELECT count(*) FROM responses_fts WHERE responses_fts MATCH ?",
                (key.lower(),),
            ).fetchone()[0] == 0, f"{key} still MATCH-able in FTS index"
    finally:
        con.close()


def test_llm_undo_restores_backup(tmp_path: Path) -> None:
    import argparse

    db = tmp_path / "io.datasette.llm" / "logs.db"
    original = _make_logs_db(db)
    source = LlmSource(root=db.parent)
    safe_write(db, _redact(source, db), backup=True, sidecars=source.sidecars(db))
    assert db.read_bytes() != original

    code = undo(argparse.Namespace(source="llm", root=db.parent))
    assert code == 0
    assert db.read_bytes() == original
    assert not db.with_name(db.name + ".bak").exists()


def test_llm_schema_drift_raises_not_silent_clean(tmp_path: Path) -> None:
    """If responses exists but has none of its expected text columns, scanning
    must fail loudly rather than report a false all-clear (cf. OpenCode #14)."""
    db = tmp_path / "io.datasette.llm" / "logs.db"
    db.parent.mkdir(parents=True)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE responses (id TEXT, note TEXT)")  # no prompt/response
    con.commit()
    con.close()

    source = LlmSource(root=db.parent)
    with pytest.raises(RuntimeError, match="llm schema drift"):
        list(source.iter_strings(db))
