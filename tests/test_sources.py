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


def test_iter_strings_records_unparseable_lines(tmp_path: Path) -> None:
    """A malformed JSONL line is skipped, but the skip must be counted (#196).

    The scanner never sees the skipped bytes, so the account is the only
    thing standing between a corrupt line and a false-clean report.
    """
    root = tmp_path / "projects"
    root.mkdir()
    target = root / "session.jsonl"
    target.write_text(
        '{"a":"valid"}\n'
        '{"broken": no-closing-brace\n'
        '{"b":"also valid"}\n'
        '{"still broken\n',
        encoding="utf-8",
    )

    src = ClaudeCodeSource(root=root)
    list(src.iter_strings(target))

    assert src.unscannable_lines == {target: 2}


def test_iter_strings_records_unreadable_file(tmp_path: Path, monkeypatch) -> None:
    """A file that cannot be read at all must be recorded, not just vanish.

    The read failure is injected (rather than chmod-000) so the test is
    deterministic on Windows, where chmod does not block reads.
    """
    root = tmp_path / "projects"
    root.mkdir()
    target = root / "session.jsonl"
    target.write_text('{"a":1}\n', encoding="utf-8")

    def _unreadable(self: Path) -> bytes:
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_bytes", _unreadable)

    src = ClaudeCodeSource(root=root)
    list(src.iter_strings(target))

    assert src.unreadable_files == [target]


def test_unscannable_accounting_survives_concurrent_workers(tmp_path: Path) -> None:
    """Concurrent workers must not lose skip records via lazy-init races (#197)."""
    from concurrent.futures import ThreadPoolExecutor

    root = tmp_path / "projects"
    root.mkdir()
    paths = []
    for i in range(200):
        target = root / f"session_{i}.jsonl"
        target.write_text('{"broken line no closing brace\n', encoding="utf-8")
        paths.append(target)

    src = ClaudeCodeSource(root=root)

    def iterate(path: Path) -> None:
        list(src.iter_strings(path))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(iterate, paths))

    assert src.unscannable_lines == {p: 1 for p in paths}, (
        f"expected one malformed-line record per file, got "
        f"{src.unscannable_lines} — records or counts were lost to a "
        f"lazy-initialization race"
    )


def test_unscannable_counts_survive_duplicate_path_workers(tmp_path: Path) -> None:
    """Duplicate profile roots submit the same file to several workers (#197).

    A repeated CLAUDE_CONFIG_DIR entry (or overlapping profile dirs) makes
    files() yield the same path more than once, so two file workers iterate
    one file on the same Source instance concurrently. The per-path count is
    a read-modify-write and must not lose increments.
    """
    from concurrent.futures import ThreadPoolExecutor

    root = tmp_path / "projects"
    root.mkdir()
    paths = []
    for i in range(50):
        target = root / f"session_{i}.jsonl"
        target.write_text('{"broken line no closing brace\n', encoding="utf-8")
        paths.append(target)

    src = ClaudeCodeSource(root=root)

    def iterate(path: Path) -> None:
        list(src.iter_strings(path))

    doubled = [*paths, *paths]  # mirror duplicate-root submission
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(iterate, doubled))

    assert src.unscannable_lines == {p: 2 for p in paths}, (
        "each submission of a path must add exactly one to its count — "
        "increments were lost to a non-atomic read-modify-write"
    )
