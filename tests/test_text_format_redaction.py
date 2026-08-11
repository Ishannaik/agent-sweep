"""End-to-end --fix tests for the non-JSONL text formats (Aider markdown,
Windsurf memory .md, OpenCode legacy / Cline / Gemini checkpoint .json).

Regression coverage for two composition bugs:

1. safe_write validated every str as JSONL, so markdown and pretty-printed
   whole-file JSON could never be written — --fix reported FAIL for half
   the advertised sources. The byte-returning workaround helpers skipped
   validation entirely and failed open (b"" on a read error would have
   truncated the file; original text on a parse error reported "redacted"
   while the secret stayed). safe_write is now format-aware (fmt=
   "jsonl"/"json"/"text", declared by Source.content_format) and the
   helpers fail closed with SafetyError.

2. Files in a source's secondary tree (Windsurf memories under ~/.codeium,
   Cursor agent transcripts under ~/.cursor) were scanned but could never
   be fixed: safety_check refused them as outside source.root, and undo
   never globbed there. Sources now declare every tree via roots().
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.pipeline import _redact_all, _scan_file, undo  # noqa: E402
from agentsweep.redactor import SafetyError, safe_write  # noqa: E402
from agentsweep.sources import (  # noqa: E402
    AiderSource,
    ClineSource,
    GeminiCliSource,
    OpenCodeSource,
    WindsurfSource,
)
from agentsweep.sources._helpers import _apply_json_file_redactions  # noqa: E402

SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example access key id


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    # Keep the audit log (and the Windsurf/Cursor secondary-tree discovery)
    # away from the real home directory.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def _scan(source, f: Path):
    """Mirror the pipeline's SCAN stage for a single file."""
    _, items, _, _, _ = _scan_file(source, f, ignores=None)
    assert items, "fixture secret should be detected"
    return {f: items}


def test_aider_markdown_fix_end_to_end(tmp_path: Path) -> None:
    root = tmp_path / "work"
    repo = root / "proj"
    repo.mkdir(parents=True)
    hist = repo / ".aider.chat.history.md"
    hist.write_text(
        "# aider chat started at 2026-06-12\n\n"
        f"#### does {SECRET} look valid to you?\n"
        "That looks like an AWS access key id.\n",
        encoding="utf-8",
    )
    original = hist.read_text(encoding="utf-8")
    source = AiderSource(root=root)
    assert hist in source.files()

    rows, errors, _ = _redact_all(source, _scan(source, hist), backup=True, force=True)
    # Before: always ("fail", ..., "line 1 is not valid JSON ...").
    assert errors == 0
    assert rows[0][0] == "ok"

    after = hist.read_text(encoding="utf-8")
    assert SECRET not in after
    assert "[REDACTED:" in after
    assert len(after.splitlines()) == len(original.splitlines())
    assert "That looks like an AWS access key id." in after
    assert hist.with_name(hist.name + ".bak").read_text(encoding="utf-8") == original


def test_opencode_legacy_json_fix_end_to_end(tmp_path: Path) -> None:
    root = tmp_path / "opencode"
    msgdir = root / "storage" / "session" / "message"
    msgdir.mkdir(parents=True)
    f = msgdir / "msg_001.json"
    f.write_text(
        json.dumps(
            {
                "role": "user",
                "parts": [{"type": "text", "text": f"my key is {SECRET}"}],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    original = f.read_text(encoding="utf-8")
    source = OpenCodeSource(root=root)
    assert source.files() == [f]

    rows, errors, _ = _redact_all(source, _scan(source, f), backup=True, force=True)
    assert errors == 0
    assert rows[0][0] == "ok"

    after = f.read_text(encoding="utf-8")
    assert SECRET not in after
    json.loads(after)  # still one valid JSON document
    assert after.endswith("\n")  # trailing newline preserved
    assert f.with_name(f.name + ".bak").read_text(encoding="utf-8") == original


def test_cline_task_json_fix_end_to_end(tmp_path: Path) -> None:
    root = tmp_path / "saoudrizwan.claude-dev"
    task = root / "tasks" / "171"
    task.mkdir(parents=True)
    f = task / "api_conversation_history.json"
    f.write_text(
        json.dumps(
            [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": f"use {SECRET} for s3"}],
                },
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    original = f.read_text(encoding="utf-8")
    source = ClineSource(root=root)
    assert source.files() == [f]

    rows, errors, _ = _redact_all(source, _scan(source, f), backup=True, force=True)
    assert errors == 0
    assert rows[0][0] == "ok"
    after = f.read_text(encoding="utf-8")
    assert SECRET not in after
    json.loads(after)
    assert f.with_name(f.name + ".bak").read_text(encoding="utf-8") == original


def test_gemini_checkpoint_json_is_scanned_and_fixed(tmp_path: Path) -> None:
    root = tmp_path / ".gemini"
    chats = root / "tmp" / "proj-1" / "chats"
    chats.mkdir(parents=True)
    f = chats / "checkpoint-main.json"
    f.write_text(
        json.dumps([{"role": "user", "parts": [{"text": f"key {SECRET}"}]}], indent=2),
        encoding="utf-8",
    )
    source = GeminiCliSource(root=root)
    assert f in source.files()

    # Regression: the inherited line-by-line JSONL parser yielded nothing
    # for pretty-printed checkpoint files, so secrets in them were
    # invisible to the scan.
    assert any(SECRET in v for _, _, v in source.iter_strings(f))

    rows, errors, _ = _redact_all(source, _scan(source, f), backup=True, force=True)
    assert errors == 0
    assert rows[0][0] == "ok"
    after = f.read_text(encoding="utf-8")
    assert SECRET not in after
    json.loads(after)


def test_windsurf_memory_fix_outside_user_root_and_undo(tmp_path: Path) -> None:
    user_root = tmp_path / "Windsurf" / "User"
    user_root.mkdir(parents=True)
    memories = tmp_path / ".codeium" / "windsurf" / "memories"  # isolated home
    memories.mkdir(parents=True)
    mem = memories / "global_rules.md"
    mem.write_text(
        f"# memories\n\n- aws key is {SECRET}\n- prefers tabs\n",
        encoding="utf-8",
    )
    original = mem.read_text(encoding="utf-8")
    source = WindsurfSource(root=user_root)
    assert mem in source.files()

    rows, errors, _ = _redact_all(source, _scan(source, mem), backup=True, force=True)
    # Before roots(): always ("skip", ..., "outside source root").
    assert errors == 0
    assert rows[0][0] == "ok"

    after = mem.read_text(encoding="utf-8")
    assert SECRET not in after
    assert "- prefers tabs" in after
    assert len(after.splitlines()) == len(original.splitlines())
    bak = mem.with_name(mem.name + ".bak")
    assert bak.read_text(encoding="utf-8") == original

    # undo must discover .md.bak in the secondary tree as well.
    code = undo(argparse.Namespace(source="windsurf", root=user_root))
    assert code == 0
    assert mem.read_text(encoding="utf-8") == original
    assert not bak.exists()


def test_safe_write_json_fmt_validates_whole_document(tmp_path: Path) -> None:
    target = tmp_path / "session.json"
    target.write_text('{\n  "a": 1\n}\n', encoding="utf-8")
    with pytest.raises(SafetyError, match="not valid JSON"):
        safe_write(target, '{\n  "a": 1,,\n}\n', backup=True, fmt="json")
    # Validation failures must leave no trace: original intact, no .bak.
    assert target.read_text(encoding="utf-8") == '{\n  "a": 1\n}\n'
    assert not target.with_name(target.name + ".bak").exists()

    record = safe_write(target, '{\n  "a": 2\n}\n', backup=True, fmt="json")
    assert record.backup is not None
    assert target.read_text(encoding="utf-8") == '{\n  "a": 2\n}\n'


def test_safe_write_text_fmt_keeps_line_count_guarantee(tmp_path: Path) -> None:
    target = tmp_path / "notes.md"
    target.write_text("# title\nsecret here\nbye\n", encoding="utf-8")
    with pytest.raises(SafetyError, match="Line count changed"):
        safe_write(target, "# title\nbye\n", backup=True, fmt="text")
    assert not target.with_name(target.name + ".bak").exists()

    # Non-JSON content is accepted when the line count is preserved —
    # the exact case the old JSONL-only validation made impossible.
    safe_write(target, "# title\n[REDACTED]\nbye\n", backup=True, fmt="text")
    assert target.read_text(encoding="utf-8") == "# title\n[REDACTED]\nbye\n"


def test_safe_write_unknown_fmt_refused(tmp_path: Path) -> None:
    target = tmp_path / "x.yaml"
    target.write_text("a: 1\n", encoding="utf-8")
    with pytest.raises(SafetyError, match="Unknown content format"):
        safe_write(target, "a: 2\n", backup=True, fmt="yaml")
    assert target.read_text(encoding="utf-8") == "a: 1\n"


def test_json_helper_fails_closed(tmp_path: Path) -> None:
    # A read failure must raise, not hand safe_write content that would
    # truncate the file (the old helper returned b"" here).
    with pytest.raises(SafetyError, match="Cannot re-read"):
        _apply_json_file_redactions(tmp_path, [])  # a directory

    # A parse failure must raise, not silently return the original
    # unredacted text (which reported "redacted" while the secret stayed).
    bad = tmp_path / "broken.json"
    bad.write_text('{"a": ', encoding="utf-8")
    with pytest.raises(SafetyError, match="no longer valid JSON"):
        _apply_json_file_redactions(bad, [])
