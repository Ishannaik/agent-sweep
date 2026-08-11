from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.redactor import SafetyError, safe_write, safety_check  # noqa: E402


def _age_file(p: Path, seconds: int) -> None:
    past = time.time() - seconds
    os.utime(p, (past, past))


def test_safe_write_creates_backup(tmp_path: Path) -> None:
    target = tmp_path / "session.jsonl"
    target.write_text('{"role":"user","content":"hi"}\n', encoding="utf-8")
    new = '{"role":"user","content":"[REDACTED]"}\n'

    record = safe_write(target, new, backup=True)

    assert target.read_text(encoding="utf-8") == new
    assert record.backup is not None
    assert record.backup.exists()
    assert (
        record.backup.read_text(encoding="utf-8") == '{"role":"user","content":"hi"}\n'
    )


def test_safe_write_refuses_existing_backup(tmp_path: Path) -> None:
    target = tmp_path / "session.jsonl"
    target.write_text('{"a":1}\n', encoding="utf-8")
    (tmp_path / "session.jsonl.bak").write_text("pre-existing", encoding="utf-8")

    with pytest.raises(SafetyError, match="Backup already exists"):
        safe_write(target, '{"a":2}\n', backup=True)


def test_safe_write_rejects_invalid_json(tmp_path: Path) -> None:
    target = tmp_path / "session.jsonl"
    target.write_text('{"role":"user"}\n', encoding="utf-8")

    with pytest.raises(SafetyError, match="not valid JSON"):
        safe_write(target, "this is not json\n", backup=True)

    assert target.read_text(encoding="utf-8") == '{"role":"user"}\n'
    assert not (tmp_path / "session.jsonl.bak").exists()


def test_safe_write_rejects_line_count_change(tmp_path: Path) -> None:
    target = tmp_path / "session.jsonl"
    target.write_text('{"a":1}\n{"b":2}\n', encoding="utf-8")

    with pytest.raises(SafetyError, match="Line count changed"):
        safe_write(target, '{"a":1}\n', backup=True)

    assert target.read_text(encoding="utf-8") == '{"a":1}\n{"b":2}\n'


def test_safe_write_no_backup_mode(tmp_path: Path) -> None:
    target = tmp_path / "session.jsonl"
    target.write_text('{"a":1}\n', encoding="utf-8")

    record = safe_write(target, '{"a":2}\n', backup=False)

    assert record.backup is None
    assert target.read_text(encoding="utf-8") == '{"a":2}\n'
    assert not (tmp_path / "session.jsonl.bak").exists()


def test_safety_check_refuses_path_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text('{"a":1}\n', encoding="utf-8")
    _age_file(outside, 3600)

    with pytest.raises(SafetyError, match="outside source root"):
        safety_check(outside, root)


def test_safety_check_refuses_symlink(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    real = root / "real.jsonl"
    real.write_text('{"a":1}\n', encoding="utf-8")
    _age_file(real, 3600)
    link = root / "link.jsonl"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires elevated privileges on this OS")
    _age_file(link, 3600)

    with pytest.raises(SafetyError, match="symlink"):
        safety_check(link, root)


def test_safety_check_refuses_symlink_pointing_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text('{"a":1}\n', encoding="utf-8")
    _age_file(outside, 3600)
    link = root / "link.jsonl"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires elevated privileges on this OS")

    with pytest.raises(SafetyError, match="outside source root|symlink"):
        safety_check(link, root)


def test_safety_check_refuses_recent_file(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "fresh.jsonl"
    target.write_text('{"a":1}\n', encoding="utf-8")

    with pytest.raises(SafetyError, match="likely an active session"):
        safety_check(target, root)


def test_safety_check_force_bypasses_mtime(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "fresh.jsonl"
    target.write_text('{"a":1}\n', encoding="utf-8")

    safety_check(target, root, force=True)


def test_safety_check_passes_old_file(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "old.jsonl"
    target.write_text('{"a":1}\n', encoding="utf-8")
    _age_file(target, 3600)

    safety_check(target, root)


def test_round_trip_preserves_structure(tmp_path: Path) -> None:
    """Verify the full write→read cycle preserves JSON structure."""
    target = tmp_path / "session.jsonl"
    original = (
        '{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}\n'
        '{"type":"assistant","message":{"content":[{"type":"text","text":"hey"}]}}\n'
    )
    target.write_text(original, encoding="utf-8")

    new = original.replace('"hi"', '"[REDACTED:example]"')
    safe_write(target, new, backup=True)

    for line in target.read_text(encoding="utf-8").splitlines():
        if line.strip():
            json.loads(line)
