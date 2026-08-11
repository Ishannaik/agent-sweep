"""Redaction-retry semantics added to fix the confusing "double backup" UX:

- safe_write is an idempotent no-op when the content is already in the target
  (redacted) state — no backup, no rewrite — so re-applying a redaction reads
  as a calm "already redacted" skip, not a scary FAIL on the no-clobber check.
- a STALE .bak with a genuine pending change still FAILs (the file would change
  but we can't clobber the backup) — that case must stay loud.
- SafetyError.force_recoverable marks only the active-session (mtime) gate, so
  callers can avoid offering --force for failures it can't fix.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.pipeline import _redact_all, _scan_file  # noqa: E402
from agentsweep.redactor import SafetyError, safe_write, safety_check  # noqa: E402
from agentsweep.sources import AiderSource  # noqa: E402

SECRET = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def test_safe_write_noop_when_content_unchanged(tmp_path: Path) -> None:
    f = tmp_path / "s.jsonl"
    f.write_bytes(b'{"a": 1}\n')  # write_bytes: no \n->\r\n translation on Windows
    rec = safe_write(f, '{"a": 1}\n', backup=True)  # byte-identical content
    assert rec.unchanged is True
    assert rec.backup is None  # no backup for a no-op
    assert not f.with_name("s.jsonl.bak").exists()
    assert f.read_text(encoding="utf-8") == '{"a": 1}\n'


def test_stale_bak_with_real_change_still_fails(tmp_path: Path) -> None:
    f = tmp_path / "s.jsonl"
    f.write_text('{"a": 1}\n', encoding="utf-8")
    f.with_name("s.jsonl.bak").write_text("leftover", encoding="utf-8")
    # A genuine change is pending but the .bak would be clobbered -> stay loud.
    with pytest.raises(SafetyError, match="Backup already exists"):
        safe_write(f, '{"a": 2}\n', backup=True)
    assert f.read_text(encoding="utf-8") == '{"a": 1}\n'  # untouched


def test_mtime_gate_is_force_recoverable(tmp_path: Path) -> None:
    f = tmp_path / "s.jsonl"
    f.write_text('{"a": 1}\n', encoding="utf-8")  # fresh -> trips the mtime gate
    with pytest.raises(SafetyError) as exc:
        safety_check(f, tmp_path, force=False)
    assert exc.value.force_recoverable is True


def test_plain_safety_error_not_force_recoverable() -> None:
    assert SafetyError("nope").force_recoverable is False


def test_rerun_redaction_skips_already_done(tmp_path: Path) -> None:
    repo = tmp_path / "work" / "proj"
    repo.mkdir(parents=True)
    hist = repo / ".aider.chat.history.md"
    hist.write_text(f"# chat\n#### key {SECRET}\nbye\n", encoding="utf-8")
    src = AiderSource(root=tmp_path / "work")

    _, items, _, _, _ = _scan_file(src, hist, ignores=None)
    fb = {hist: items}

    rows, errors, recoverable = _redact_all(src, fb, backup=True, force=True)
    assert errors == 0 and rows[0][0] == "ok"
    assert SECRET not in hist.read_text(encoding="utf-8")

    # Re-run with the SAME cached findings (the force-retry path): the file is
    # already redacted, so it's a calm skip — NOT a "Backup already exists" FAIL.
    rows2, errors2, recoverable2 = _redact_all(src, fb, backup=True, force=True)
    assert errors2 == 0
    assert rows2[0][0] == "skip"
    assert "already redacted" in rows2[0][2]
    assert recoverable2 is False
