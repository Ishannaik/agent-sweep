"""Backup hygiene: .bak permissions and the `purge` verb.

The .bak files safe_write leaves behind hold the pre-redaction
originals — plaintext secrets. Two gaps closed here:

1. Backups were created via Path.write_bytes, i.e. with default-umask
   permissions (usually world-readable). They are now opened with
   O_CREAT | O_EXCL and mode 0o600, which also makes the existing
   no-clobber check race-free.
2. The documented final step of a sweep — "rotate the keys, then delete
   the .bak files" — had no command. `agentsweep purge` deletes the
   backups for a source (all roots, all backup globs), prompting on a
   terminal and refusing without --yes everywhere else.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.pipeline import purge  # noqa: E402
from agentsweep.redactor import SafetyError, safe_write  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    # Keep the audit log (and Windsurf secondary-tree discovery) away from
    # the real home directory.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def _ns(**kwargs) -> argparse.Namespace:
    base = {"source": "aider", "root": None, "yes": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX permission bits are not meaningful on Windows")
def test_backup_is_created_owner_only(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "session.jsonl"
    target.write_text('{"a": "secret"}\n', encoding="utf-8")
    # A permissive umask must not leak into the backup's mode.
    old_umask = os.umask(0o000)
    try:
        record = safe_write(target, '{"a": "[REDACTED]"}\n', backup=True)
    finally:
        os.umask(old_umask)
    assert record.backup is not None
    mode = stat.S_IMODE(record.backup.stat().st_mode)
    assert mode == 0o600, f"backup mode is {oct(mode)}, expected 0o600"


def test_backup_no_clobber_still_enforced(tmp_path: Path) -> None:
    target = tmp_path / "session.jsonl"
    target.write_text('{"a": 1}\n', encoding="utf-8")
    bak = tmp_path / "session.jsonl.bak"
    bak.write_text("previous backup", encoding="utf-8")
    with pytest.raises(SafetyError, match="Backup already exists"):
        safe_write(target, '{"a": 2}\n', backup=True)
    assert bak.read_text(encoding="utf-8") == "previous backup"
    assert target.read_text(encoding="utf-8") == '{"a": 1}\n'


def test_purge_deletes_backups_with_yes(tmp_path: Path) -> None:
    root = tmp_path / "work"
    repo = root / "proj"
    repo.mkdir(parents=True)
    hist = repo / ".aider.chat.history.md"
    hist.write_text("# redacted\n", encoding="utf-8")
    bak = repo / ".aider.chat.history.md.bak"
    bak.write_text("# original with secret\n", encoding="utf-8")

    code = purge(_ns(root=root, yes=True))
    assert code == 0
    assert not bak.exists()
    assert hist.exists()  # only backups are deleted, never the histories


def test_purge_noninteractive_refuses_without_yes(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    bak = root / ".aider.chat.history.md.bak"
    bak.write_text("# original with secret\n", encoding="utf-8")

    # Under pytest stdin is not a tty, so this is the script path.
    code = purge(_ns(root=root, yes=False))
    assert code == 2
    assert bak.exists()  # nothing deleted without explicit consent


def test_purge_nothing_to_do(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    assert purge(_ns(root=root, yes=True)) == 0


def test_purge_covers_secondary_roots(tmp_path: Path) -> None:
    # Windsurf memories live outside the User root (under the isolated
    # home); purge must glob backups there too, like undo does.
    from agentsweep.sources import WindsurfSource  # noqa: PLC0415

    user_root = tmp_path / "Windsurf" / "User"
    user_root.mkdir(parents=True)
    memories = tmp_path / ".codeium" / "windsurf" / "memories"
    memories.mkdir(parents=True)
    bak = memories / "global_rules.md.bak"
    bak.write_text("- aws key was here\n", encoding="utf-8")

    source = WindsurfSource(root=user_root)
    assert any(bak.is_relative_to(r) for r in source.roots())

    code = purge(_ns(source="windsurf", root=user_root, yes=True))
    assert code == 0
    assert not bak.exists()
