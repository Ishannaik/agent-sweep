"""Base abstractions: Source ABC, JsonlSource, and JSON-walk helpers."""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

KeyPath = list  # list of str (dict keys) or int (list indices)


class Source(ABC):
    """Adapter for a specific AI coding agent's on-disk history format."""

    name: str
    display_name: str
    root: Path
    process_markers: tuple[str, ...] = ()
    # True when this source's storage path/format was derived from research
    # but has NOT been confirmed against a real install — scanning is safe
    # (a wrong path just finds nothing) but may under-report. Surfaced in the
    # picker, the scan banner, and the README so users know what's verified.
    experimental: bool = False

    @abstractmethod
    def files(self) -> list[Path]:
        """Return every history file to scan under this source's root."""

    def iter_files(self) -> Iterator[Path]:
        """Yield history files one by one (default: iterate over files()).

        Override in subclasses where streaming discovery is possible so that
        callers can show a live counter without waiting for the full list.
        """
        yield from self.files()

    @abstractmethod
    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        """Yield (line_number, keypath, value) for every string in the file.

        line_number is 1-indexed. keypath is a list of dict keys / list indices
        that locates the string inside the file's structure. value is the raw
        string content.
        """

    @abstractmethod
    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        """Produce the new file content with string values replaced.

        Each redaction is (line_number, keypath, new_string). The return
        value is the full file content to write — str for text formats,
        bytes for binary formats like SQLite. Implementations MUST NOT
        modify `path` itself; the redactor owns the backup and the atomic
        write. str content MUST satisfy the validation declared by
        content_format() for this path (JSONL, whole-file JSON, or
        line-count-preserving text); bytes content MUST be validated by
        the implementation (e.g. PRAGMA integrity_check) before it is
        returned.
        """

    def content_format(self, path: Path) -> str:
        """Declare how the redactor must validate str content for `path`.

        One of "jsonl" (the default: every line parses as JSON, line count
        preserved), "json" (the whole file parses as one JSON document) or
        "text" (markdown/plaintext: line count preserved). Only consulted
        when apply_redactions returns str — bytes returns are validated by
        the source itself before being handed over.
        """
        return "jsonl"

    def sidecars(self, path: Path) -> list[Path]:
        """Files that carry part of `path`'s committed state on disk.

        A SQLite database in WAL mode keeps freshly committed pages in
        `<db>-wal` until a checkpoint folds them back into the database.
        Those pages hold the same plaintext the database does, and SQLite
        replays them over whatever database file it finds on the next open.
        Replacing the database without also retiring them would leave the
        secret on disk and let the next open undo the redaction.

        Only files that exist are returned. Sources whose apply_redactions
        returns bytes built from a full `sqlite3.Connection.backup()` — which
        folds the WAL into the copy — override this so the redactor can back
        the sidecars up and delete them after the atomic replace.
        """
        return []

    def roots(self) -> list[Path]:
        """Every directory tree this source's files may live under.

        Most sources have exactly one (self.root); sources whose history
        spans extra trees (Cursor agent transcripts, Windsurf memories)
        override this. files() must stay within these — the redactor's
        path-containment check and undo's backup discovery rely on it.
        """
        return [self.root]


class JsonlSource(Source):
    """Shared implementation for agents that store history as JSONL files."""

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        raise NotImplementedError

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.rglob("*.jsonl") if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        """Yield JSONL files as rglob discovers them (no full-list sort)."""
        if not self.root.exists():
            return
        for p in self.root.rglob("*.jsonl"):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        try:
            raw = path.read_bytes()  # ~1.5x faster than read_text on Windows
        except OSError:
            return
        for i, bline in enumerate(raw.splitlines(), 1):
            if not bline.strip():
                continue
            try:
                obj = json.loads(bline)  # json.loads accepts bytes natively
            except (json.JSONDecodeError, ValueError):
                continue
            yield from _walk_json(obj, [], i)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)

        by_line: dict[int, list[tuple[KeyPath, str]]] = {}
        for line_num, kp, new_val in redactions:
            by_line.setdefault(line_num, []).append((kp, new_val))

        out: list[str] = []
        for i, line in enumerate(lines, 1):
            if i not in by_line or not line.strip():
                out.append(line)
                continue
            ending = _line_ending(line)
            body = line[: len(line) - len(ending)]
            try:
                obj = json.loads(body)
            except json.JSONDecodeError:
                out.append(line)
                continue
            for kp, new_val in by_line[i]:
                _set_by_path(obj, kp, new_val)
            out.append(json.dumps(obj, ensure_ascii=False) + ending)
        return "".join(out)


# ---------------------------------------------------------------------------
# JSON-walk helpers (shared by all source modules)
# ---------------------------------------------------------------------------

def _walk_json_with_base(
    obj,
    base_kp: KeyPath,
    line_num: int,
) -> Iterator[tuple[int, KeyPath, str]]:
    """Like _walk_json but prepends base_kp to every yielded keypath."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                yield (line_num, base_kp + [k], v)
            elif isinstance(v, (dict, list)):
                yield from _walk_json_with_base(v, base_kp + [k], line_num)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                yield (line_num, base_kp + [i], v)
            elif isinstance(v, (dict, list)):
                yield from _walk_json_with_base(v, base_kp + [i], line_num)


def _walk_json(obj, path: KeyPath, line_num: int) -> Iterator[tuple[int, KeyPath, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                yield (line_num, path + [k], v)
            elif isinstance(v, (dict, list)):
                yield from _walk_json(v, path + [k], line_num)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                yield (line_num, path + [i], v)
            elif isinstance(v, (dict, list)):
                yield from _walk_json(v, path + [i], line_num)


def _set_by_path(obj, path: KeyPath, value) -> None:
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value


def _line_ending(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    return ""
