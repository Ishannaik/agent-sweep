"""Persisted-redaction verification regressions."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.ignore import IgnoreSet  # noqa: E402
from agentsweep.pipeline import _redact_all, _scan_file  # noqa: E402
from agentsweep.redactor import (  # noqa: E402
    RedactionTarget,
    RedactionVerification,
    SafetyError,
    safe_write,
)
from agentsweep.sources import (  # noqa: E402
    AiderSource,
    ClineSource,
    CursorSource,
    OpenCodeSource,
    WarpSource,
    WindsurfSource,
)
from agentsweep.sources._base import JsonlSource  # noqa: E402


AWS_A = "AKIA" + "A" * 16
AWS_B = "AKIA" + "B" * 16
MNEMONIC = "abandon " * 11 + "about"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate all source-home discovery from the real user profile."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


class _TestJsonlSource(JsonlSource):
    """Base source whose tests must provide an explicit history root."""

    name = "test"
    display_name = "Test"

    @classmethod
    def default_root(cls) -> Path:
        """Reject implicit root discovery in verification fixtures."""
        raise AssertionError("tests always provide root")


class _NoopJsonlSource(_TestJsonlSource):
    """Adapter fixture that returns unchanged content for rejection checks."""

    def apply_redactions(self, path: Path, redactions: list) -> str:
        """Decode exact source bytes so a no-op preserves every newline byte."""
        return path.read_bytes().decode("utf-8")


class _PartialJsonlSource(_TestJsonlSource):
    """Adapter fixture that leaves one selected secret in its output."""

    def apply_redactions(self, path: Path, redactions: list) -> str:
        """Produce a superficially redacted value that fails verification."""
        redacted = super().apply_redactions(path, redactions)
        return redacted.replace("[REDACTED:aws-access-key]", f"[REDACTED] {AWS_A}", 1)


class _SilentReaderJsonlSource(_TestJsonlSource):
    """Reader fixture that hides redacted content after a write."""

    def iter_strings(self, path: Path):
        """Simulate a faulty reader that suppresses post-redaction strings."""
        if "[REDACTED:" in path.read_text(encoding="utf-8"):
            return
        yield from super().iter_strings(path)


def _history(root: Path, value: str) -> Path:
    """Create a platform-native JSONL history fixture for general cases."""
    root.mkdir()
    path = root / "session.jsonl"
    path.write_text(json.dumps({"message": value}) + "\n", encoding="utf-8")
    return path


def _found(source: JsonlSource, path: Path, ignores=None):
    """Return scanned targets while requiring this fixture to contain a secret."""
    _, items, _, _, _ = _scan_file(source, path, ignores=ignores)
    assert items
    return {path: items}


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_rejects_noop_adapter_without_backup_or_audit(
    tmp_path: Path, newline: bytes
) -> None:
    """Reject byte-identical no-op output before backup or audit side effects."""
    root = tmp_path / "history"
    root.mkdir()
    path = root / "session.jsonl"
    original = json.dumps({"message": f"key {AWS_A}"}).encode("utf-8") + newline
    path.write_bytes(original)

    rows, errors, _recoverable = _redact_all(
        _NoopJsonlSource(root=root),
        _found(_NoopJsonlSource(root=root), path),
        backup=True,
        force=True,
    )

    assert errors == 1
    assert rows[0][0] == "fail"
    assert AWS_A not in rows[0][2]
    assert AWS_A in path.read_text(encoding="utf-8")
    assert path.read_bytes() == original
    assert not path.with_name(path.name + ".bak").exists()
    assert not (tmp_path / ".agentsweep" / "audit.jsonl").exists()


def test_rejects_partial_adapter_with_selected_secret_still_present(
    tmp_path: Path,
) -> None:
    """Reject output that leaves the selected secret after partial redaction."""
    root = tmp_path / "history"
    path = _history(root, f"key {AWS_A}")
    source = _PartialJsonlSource(root=root)

    rows, errors, _recoverable = _redact_all(
        source, _found(source, path), backup=True, force=True
    )

    assert errors == 1
    assert rows[0][0] == "fail"
    assert (
        path.read_text(encoding="utf-8")
        == json.dumps({"message": f"key {AWS_A}"}) + "\n"
    )


def test_rejects_silently_empty_postwrite_reader(tmp_path: Path) -> None:
    """Reject a writer whose post-write reader falsely yields no content."""
    root = tmp_path / "history"
    path = _history(root, f"key {AWS_A}")
    source = _SilentReaderJsonlSource(root=root)
    original = path.read_bytes()

    rows, errors, _recoverable = _redact_all(
        source, _found(source, path), backup=False, force=True
    )

    assert errors == 1
    assert rows[0][0] == "fail"
    assert path.read_bytes() == original
    assert not path.with_name(path.name + ".bak").exists()


def test_rejects_changed_persisted_bytes_and_restores_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restore original bytes when post-write persistence is tampered with."""
    import agentsweep.redactor as redactor

    root = tmp_path / "history"
    path = _history(root, f"key {AWS_A}")
    source = _TestJsonlSource(root=root)
    original = path.read_bytes()
    real_replace = os.replace
    tampered = False

    def replace_then_tamper(src, dst) -> None:
        """Inject one replacement-time mutation into the staged destination."""
        nonlocal tampered
        real_replace(src, dst)
        if not tampered and Path(dst) == path and Path(src).suffix == ".tmp":
            tampered = True
            path.write_text(
                json.dumps({"message": f"key {AWS_A}"}) + "\n", encoding="utf-8"
            )

    monkeypatch.setattr(redactor.os, "replace", replace_then_tamper)
    rows, errors, _recoverable = _redact_all(
        source, _found(source, path), backup=True, force=True
    )

    assert errors == 1
    assert rows[0][0] == "fail"
    assert path.read_bytes() == original


def test_rollback_failure_keeps_backup_and_recovery_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep backup and restore artifact when rollback itself cannot complete."""
    import agentsweep.redactor as redactor

    root = tmp_path / "history"
    path = _history(root, f"key {AWS_A}")
    source = _PartialJsonlSource(root=root)
    original = path.read_bytes()
    real_replace = os.replace

    def fail_only_rollback(src, dst) -> None:
        """Fail only the restore rename so the prepared artifact remains."""
        if Path(src).suffix == ".restore":
            raise OSError("synthetic rollback failure")
        real_replace(src, dst)

    monkeypatch.setattr(redactor.os, "replace", fail_only_rollback)
    rows, errors, _recoverable = _redact_all(
        source, _found(source, path), backup=True, force=True
    )

    assert errors == 1
    assert rows[0][0] == "fail"
    restore_files = list(path.parent.glob(f".{path.name}.*.restore"))
    assert restore_files
    assert restore_files[0].read_bytes() == original
    assert path.with_name(path.name + ".bak").read_bytes() == original
    assert not (tmp_path / ".agentsweep" / "audit.jsonl").exists()


@pytest.mark.parametrize("failure", ["allocate", "fsync"])
def test_no_backup_refuses_when_prewrite_recovery_cannot_persist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    """Refuse writes when no-backup recovery cannot be durably prepared."""
    import agentsweep.redactor as redactor

    root = tmp_path / "history"
    path = _history(root, f"key {AWS_A}")
    source = _PartialJsonlSource(root=root)
    original = path.read_bytes()
    if failure == "allocate":
        real_mkstemp = redactor.tempfile.mkstemp

        def fail_recovery_mkstemp(*args, **kwargs):
            """Fail recovery-file allocation without affecting other temp files."""
            if kwargs.get("suffix") == ".recover":
                raise OSError("synthetic recovery allocation failure")
            return real_mkstemp(*args, **kwargs)

        monkeypatch.setattr(redactor.tempfile, "mkstemp", fail_recovery_mkstemp)
    else:
        monkeypatch.setattr(
            redactor.os,
            "fsync",
            lambda _fd: (_ for _ in ()).throw(OSError("synthetic fsync failure")),
        )

    rows, errors, _recoverable = _redact_all(
        source, _found(source, path), backup=False, force=True
    )

    assert errors == 1
    assert rows[0][0] == "fail"
    assert path.read_bytes() == original
    assert not list(path.parent.glob(f".{path.name}.*.recover"))
    assert not (tmp_path / ".agentsweep" / "audit.jsonl").exists()


def test_no_backup_rollback_failure_retains_prepared_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain prepared recovery bytes when no-backup rollback cannot run."""
    import agentsweep.redactor as redactor

    root = tmp_path / "history"
    path = _history(root, f"key {AWS_A}")
    source = _PartialJsonlSource(root=root)
    original = path.read_bytes()
    real_replace = os.replace

    def fail_prepared_recovery(src, dst) -> None:
        """Fail only the recovery promotion after the write needs rollback."""
        if Path(src).suffix == ".recover":
            raise OSError("synthetic prepared recovery failure")
        real_replace(src, dst)

    monkeypatch.setattr(redactor.os, "replace", fail_prepared_recovery)
    rows, errors, _recoverable = _redact_all(
        source, _found(source, path), backup=False, force=True
    )

    assert errors == 1
    assert rows[0][0] == "fail"
    recovery_files = list(path.parent.glob(f".{path.name}.*.recover"))
    assert recovery_files
    assert recovery_files[0].read_bytes() == original
    assert not path.with_name(path.name + ".bak").exists()
    assert not (tmp_path / ".agentsweep" / "audit.jsonl").exists()


def test_permits_ignored_unselected_same_rule_at_same_location(tmp_path: Path) -> None:
    """Allow an ignored survivor sharing a rule and location with a target."""
    root = tmp_path / "history"
    path = _history(root, f"keys {AWS_A} and {AWS_B}")
    source = _TestJsonlSource(root=root)
    ignores = IgnoreSet()
    ignores.add_line(AWS_B)

    rows, errors, _recoverable = _redact_all(
        source,
        _found(source, path, ignores=ignores),
        backup=True,
        force=True,
    )

    after = path.read_text(encoding="utf-8")
    assert errors == 0
    assert rows[0][0] == "ok"
    assert AWS_A not in after
    assert AWS_B in after
    assert "[REDACTED:aws-access-key]" in after


def test_verifies_multiline_function_detector_in_decoded_jsonl(tmp_path: Path) -> None:
    """Verify multiline detector matches disappear from decoded JSONL content."""
    root = tmp_path / "history"
    phrase = MNEMONIC.replace(" ", "\n", 3)
    path = _history(root, phrase)
    source = _TestJsonlSource(root=root)

    rows, errors, _recoverable = _redact_all(
        source, _found(source, path), backup=True, force=True
    )

    after = path.read_text(encoding="utf-8")
    assert errors == 0
    assert rows[0][0] == "ok"
    assert "[REDACTED:bip39-mnemonic]" in after
    assert "abandon" not in after


def test_verifies_whole_json_source(tmp_path: Path) -> None:
    """Verify whole-JSON sources only succeed after selected values disappear."""
    root = tmp_path / "cline"
    task = root / "tasks" / "1"
    task.mkdir(parents=True)
    path = task / "api_conversation_history.json"
    path.write_text(json.dumps([{"text": f"key {AWS_A}"}], indent=2), encoding="utf-8")
    source = ClineSource(root=root)

    rows, errors, _recoverable = _redact_all(
        source, _scan_items(source, path), backup=True, force=True
    )

    assert errors == 0
    assert rows[0][0] == "ok"
    assert AWS_A not in path.read_text(encoding="utf-8")


def test_verifies_plaintext_source(tmp_path: Path) -> None:
    """Verify plaintext histories persist selected-secret redaction."""
    root = tmp_path / "aider"
    project = root / "project"
    project.mkdir(parents=True)
    path = project / ".aider.chat.history.md"
    path.write_text(f"key {AWS_A}\n", encoding="utf-8")
    source = AiderSource(root=root)

    rows, errors, _recoverable = _redact_all(
        source, _scan_items(source, path), backup=True, force=True
    )

    assert errors == 0
    assert rows[0][0] == "ok"
    assert AWS_A not in path.read_text(encoding="utf-8")


def test_cursor_transcript_verifies_with_overlapping_custom_root(
    tmp_path: Path,
) -> None:
    """Verify a custom Cursor root does not bypass persisted-content checks."""
    root = tmp_path / ".cursor"
    path = root / "projects" / "project" / "agent-transcripts" / "session.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"message": f"key {AWS_A}"}) + "\n", encoding="utf-8")
    source = CursorSource(root=root)
    original = path.read_bytes()

    rows, errors, _recoverable = _redact_all(
        source, _scan_items(source, path), backup=True, force=True
    )

    assert errors == 0
    assert rows[0][0] == "ok"
    assert AWS_A not in path.read_text(encoding="utf-8")
    assert path.with_name(path.name + ".bak").read_bytes() == original


def test_windsurf_memory_verifies_with_overlapping_custom_root(
    tmp_path: Path,
) -> None:
    """Verify a custom Windsurf root does not bypass persisted-content checks."""
    root = tmp_path
    path = root / ".codeium" / "windsurf" / "memories" / "rules.md"
    path.parent.mkdir(parents=True)
    path.write_text(f"key {AWS_A}\n", encoding="utf-8")
    source = WindsurfSource(root=root)
    original = path.read_bytes()

    rows, errors, _recoverable = _redact_all(
        source, _scan_items(source, path), backup=True, force=True
    )

    assert errors == 0
    assert rows[0][0] == "ok"
    assert AWS_A not in path.read_text(encoding="utf-8")
    assert path.with_name(path.name + ".bak").read_bytes() == original


def test_verifies_sqlite_source(tmp_path: Path) -> None:
    """Verify SQLite content is rescanned after a selected value is replaced."""
    root = tmp_path / "User"
    path = root / "globalStorage" / "state.vscdb"
    path.parent.mkdir(parents=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO ItemTable VALUES (?, ?)", ("chat", f"key {AWS_A}"))
    con.commit()
    con.close()
    source = CursorSource(root=root)

    rows, errors, _recoverable = _redact_all(
        source, _scan_items(source, path), backup=True, force=True
    )

    assert errors == 0
    assert rows[0][0] == "ok"
    con = sqlite3.connect(path)
    value = con.execute("SELECT value FROM ItemTable").fetchone()[0]
    con.close()
    assert AWS_A not in value
    assert "[REDACTED:aws-access-key]" in value


def test_verifies_sparse_sqlite_rows_with_ignored_survivor(tmp_path: Path) -> None:
    """Verify sparse SQLite rows retain ignored survivors while redacting targets."""
    root = tmp_path / "opencode"
    path = root / "opencode.db"
    root.mkdir()
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE part (id TEXT, content TEXT)")
    con.execute("INSERT INTO part VALUES (?, ?)", ("clean", "ordinary text"))
    con.execute("INSERT INTO part VALUES (?, ?)", ("selected", f"key {AWS_A}"))
    con.execute("INSERT INTO part VALUES (?, ?)", ("ignored", f"key {AWS_B}"))
    con.execute("DELETE FROM part WHERE id = ?", ("clean",))
    con.commit()
    con.close()
    source = OpenCodeSource(root=root)
    ignores = IgnoreSet()
    ignores.add_line(AWS_B)

    rows, errors, _recoverable = _redact_all(
        source,
        _found(source, path, ignores=ignores),
        backup=True,
        force=True,
    )

    assert errors == 0
    assert rows[0][0] == "ok"
    con = sqlite3.connect(path)
    values = dict(con.execute("SELECT id, content FROM part"))
    con.close()
    assert values["selected"] == "key [REDACTED:aws-access-key]"
    assert values["ignored"] == f"key {AWS_B}"


def test_generic_sqlite_source_verifies_multiple_targeted_columns(
    tmp_path: Path,
) -> None:
    """Verify generic SQLite sources rescan every targeted text column."""
    root = tmp_path / "warp"
    root.mkdir()
    path = root / "warp.sqlite"
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE agent_conversations (role TEXT, content TEXT, summary TEXT)"
    )
    con.execute(
        "INSERT INTO agent_conversations VALUES (?, ?, ?)",
        ("user", f"key {AWS_A}", f"key {AWS_B}"),
    )
    con.commit()
    con.close()
    source = WarpSource(root=root)

    rows, errors, _recoverable = _redact_all(
        source,
        _scan_items(source, path),
        backup=True,
        force=True,
    )

    assert errors == 0
    assert rows[0][0] == "ok"
    con = sqlite3.connect(path)
    content, summary = con.execute(
        "SELECT content, summary FROM agent_conversations"
    ).fetchone()
    con.close()
    assert AWS_A not in content
    assert AWS_B not in summary


def test_rejects_sqlite_redaction_that_changes_immutable_row_metadata(
    tmp_path: Path,
) -> None:
    """Reject SQLite output that changes immutable identity metadata."""

    class _WrongRowOpenCodeSource(OpenCodeSource):
        """Adapter fixture that mutates selected-row identity after redaction."""

        def apply_redactions(self, path: Path, redactions: list) -> bytes:
            """Stage redacted bytes with an invalid selected-row identity."""
            redacted = super().apply_redactions(path, redactions)
            staged = path.with_name("wrong-row.db")
            try:
                staged.write_bytes(redacted)
                con = sqlite3.connect(staged)
                con.execute(
                    "UPDATE part SET id = ? WHERE id = ?", ("moved", "selected")
                )
                con.commit()
                con.close()
                return staged.read_bytes()
            finally:
                staged.unlink(missing_ok=True)

    root = tmp_path / "opencode"
    path = root / "opencode.db"
    root.mkdir()
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE part (id TEXT, content TEXT)")
    con.execute("INSERT INTO part VALUES (?, ?)", ("selected", f"key {AWS_A}"))
    con.commit()
    con.close()
    original = path.read_bytes()
    source = _WrongRowOpenCodeSource(root=root)

    rows, errors, _recoverable = _redact_all(
        source, _found(source, path), backup=True, force=True
    )

    assert errors == 1
    assert rows[0][0] == "fail"
    assert path.read_bytes() == original
    assert path.with_name(path.name + ".bak").read_bytes() == original


def test_unknown_fired_detector_refuses_before_write(tmp_path: Path) -> None:
    """Refuse unknown detector output before it can write or create a backup."""
    root = tmp_path / "history"
    path = _history(root, "ordinary text")
    source = _TestJsonlSource(root=root)
    target = RedactionTarget(
        line=1,
        keypath=("message",),
        original="ordinary text",
        replacement="[REDACTED:unknown]",
        rule="unknown-detector",
        span=(0, 0),
    )

    with pytest.raises(SafetyError, match="no valid fired detector"):
        safe_write(
            path,
            json.dumps({"message": "[REDACTED:unknown]"}) + "\n",
            verification=RedactionVerification(source=source, targets=(target,)),
        )
    assert not path.with_name(path.name + ".bak").exists()
    assert "ordinary text" in path.read_text(encoding="utf-8")


def _scan_items(source, path: Path):
    """Return selected scan targets while requiring the fixture to be detected."""
    _, items, _, _, _ = _scan_file(source, path, ignores=None)
    assert items
    return {path: items}
