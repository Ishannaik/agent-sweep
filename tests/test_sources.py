from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.sources import ClaudeCodeSource  # noqa: E402


FIXTURE = Path(__file__).parent / "fixtures" / "claude-code" / "sample.jsonl"


def test_iter_strings_finds_nested_content(tmp_path: Path) -> None:
    root = tmp_path / "projects"
    root.mkdir()
    target = root / "session.jsonl"
    target.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    src = ClaudeCodeSource(root=root)
    strings = list(src.iter_strings(target))

    values = [v for _, _, v in strings]
    assert any("AKIAIOSFODNN7EXAMPLE" in v for v in values)
    assert any("ghp_1234567890abcdefghijklmnopqrstuvwxyz" in v for v in values)


def test_apply_redactions_preserves_json_validity(tmp_path: Path) -> None:
    root = tmp_path / "projects"
    root.mkdir()
    target = root / "session.jsonl"
    target.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    src = ClaudeCodeSource(root=root)
    original_lines = target.read_text(encoding="utf-8").splitlines()

    redactions = []
    for line_num, kp, value in src.iter_strings(target):
        if "AKIAIOSFODNN7EXAMPLE" in value:
            redactions.append(
                (line_num, kp, value.replace("AKIAIOSFODNN7EXAMPLE", "[REDACTED]"))
            )

    assert redactions, "fixture should contain the AWS key"
    new_content = src.apply_redactions(target, redactions)

    new_lines = new_content.splitlines()
    assert len(new_lines) == len(original_lines)

    for line in new_lines:
        if line.strip():
            json.loads(line)

    assert "AKIAIOSFODNN7EXAMPLE" not in new_content
    assert "[REDACTED]" in new_content


def test_files_returns_empty_when_root_missing(tmp_path: Path) -> None:
    src = ClaudeCodeSource(root=tmp_path / "does-not-exist")
    assert src.files() == []


def test_files_ignores_non_jsonl(tmp_path: Path) -> None:
    root = tmp_path / "projects"
    root.mkdir()
    (root / "session.jsonl").write_text('{"a":1}\n', encoding="utf-8")
    (root / "readme.md").write_text("hello", encoding="utf-8")

    src = ClaudeCodeSource(root=root)
    files = src.files()
    assert len(files) == 1
    assert files[0].name == "session.jsonl"
