"""VS Code-based SQLite sources: _VSCodeSqliteSource, Cursor, Windsurf."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Iterator

from ..preflight import (
    CURSOR_MARKERS,
    WINDSURF_MARKERS,
)
from ._base import KeyPath, Source, _walk_json_with_base
from ._helpers import (
    _apply_jsonl_redactions,
    _apply_plaintext_redactions,
    _iter_jsonl_strings,
    _iter_plaintext_lines,
    _redact_sqlite_copy,
)


class _VSCodeSqliteSource(Source):
    """Shared base for VS Code-fork agents (Cursor, Windsurf) that store
    history in SQLite state.vscdb files under globalStorage and workspaceStorage.

    Subclasses must supply:
      - name / display_name / process_markers
      - default_root() -> Path  (the "User" directory)
    """

    _SQLITE_SENTINEL = "__sqlite_row__"

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        raise NotImplementedError

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.rglob("*.vscdb") if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        for p in self.root.rglob("*.vscdb"):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except (sqlite3.OperationalError, sqlite3.DatabaseError):
            return
        try:
            for table, col in self._sqlite_text_columns(con):
                try:
                    cur = con.execute(
                        f"SELECT rowid, {col} FROM {table}"  # noqa: S608
                    )
                except sqlite3.OperationalError:
                    continue
                for rowid, value in cur:
                    if not isinstance(value, str) or not value:
                        continue
                    try:
                        obj = json.loads(value)
                        kp_base: KeyPath = [table, rowid, col]
                        yield from _walk_json_with_base(obj, kp_base, max(rowid, 1))
                    except (json.JSONDecodeError, TypeError):
                        yield (max(rowid, 1), [table, rowid, col], value)
        finally:
            con.close()

    def _sqlite_text_columns(self, con: sqlite3.Connection) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        known = {
            "cursorDiskKV": ["value"],
            "ItemTable": ["value"],
        }
        try:
            tables = {
                row[0]
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        except sqlite3.OperationalError:
            return pairs
        for table, cols in known.items():
            if table not in tables:
                continue
            for col in cols:
                pairs.append((table, col))
        return pairs

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> bytes:
        return _redact_sqlite_copy(path, redactions, self._sqlite_text_columns)


class CursorSource(_VSCodeSqliteSource):
    """Cursor IDE (Anysphere) — history in state.vscdb files under the Cursor
    User directory.  Two stores are scanned:

    - globalStorage/state.vscdb  — all-time conversation blobs
    - workspaceStorage/*/state.vscdb — per-workspace copies

    Agent-transcript JSONL files under ~/.cursor/projects/*/agent-transcripts/
    are also discovered and scanned via a secondary JSONL pass.
    """

    name = "cursor"
    display_name = "Cursor IDE"
    process_markers = CURSOR_MARKERS

    @classmethod
    def _appdata_base(cls) -> Path:
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                return Path(appdata)
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support"
        return Path(os.environ.get("XDG_CONFIG_HOME", "")) or (Path.home() / ".config")

    @classmethod
    def default_root(cls) -> Path:
        return cls._appdata_base() / "Cursor" / "User"

    def _agent_transcripts_root(self) -> Path:
        return Path.home() / ".cursor" / "projects"

    def roots(self) -> list[Path]:
        return [self.root, self._agent_transcripts_root()]

    def files(self) -> list[Path]:
        result: list[Path] = []
        if self.root.exists():
            result.extend(sorted(p for p in self.root.rglob("*.vscdb") if p.is_file()))
        transcripts_root = self._agent_transcripts_root()
        if transcripts_root.exists():
            result.extend(
                sorted(p for p in transcripts_root.rglob("*.jsonl") if p.is_file())
            )
        return result

    def iter_files(self) -> Iterator[Path]:
        if self.root.exists():
            for p in self.root.rglob("*.vscdb"):
                if p.is_file():
                    yield p
        transcripts_root = self._agent_transcripts_root()
        if transcripts_root.exists():
            for p in transcripts_root.rglob("*.jsonl"):
                if p.is_file():
                    yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        if path.suffix == ".jsonl":
            yield from _iter_jsonl_strings(path)
        else:
            yield from super().iter_strings(path)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        if path.suffix == ".jsonl":
            return _apply_jsonl_redactions(path, redactions)
        return super().apply_redactions(path, redactions)


class WindsurfSource(_VSCodeSqliteSource):
    """Windsurf IDE (Codeium / Cascade) — state.vscdb SQLite files under the
    Windsurf User directory, with the same globalStorage/workspaceStorage layout
    as Cursor.

    Additionally, Codeium memory markdown files under
    ~/.codeium/windsurf/memories/ are scanned as plain-text.
    """

    name = "windsurf"
    display_name = "Windsurf IDE"
    process_markers = WINDSURF_MARKERS

    @classmethod
    def _appdata_base(cls) -> Path:
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                return Path(appdata)
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support"
        return Path(os.environ.get("XDG_CONFIG_HOME", "")) or (Path.home() / ".config")

    @classmethod
    def default_root(cls) -> Path:
        return cls._appdata_base() / "Windsurf" / "User"

    def _memories_root(self) -> Path:
        return Path.home() / ".codeium" / "windsurf" / "memories"

    def roots(self) -> list[Path]:
        return [self.root, self._memories_root()]

    def files(self) -> list[Path]:
        result: list[Path] = []
        if self.root.exists():
            result.extend(sorted(p for p in self.root.rglob("*.vscdb") if p.is_file()))
        memories = self._memories_root()
        if memories.exists():
            result.extend(sorted(p for p in memories.rglob("*.md") if p.is_file()))
        return result

    def iter_files(self) -> Iterator[Path]:
        if self.root.exists():
            for p in self.root.rglob("*.vscdb"):
                if p.is_file():
                    yield p
        memories = self._memories_root()
        if memories.exists():
            for p in memories.rglob("*.md"):
                if p.is_file():
                    yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        if path.suffix == ".md":
            yield from _iter_plaintext_lines(path)
        else:
            yield from super().iter_strings(path)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        if path.suffix == ".md":
            return _apply_plaintext_redactions(path, redactions)
        return super().apply_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        # .md memories are plaintext; .vscdb redactions return
        # source-validated bytes (fmt unused).
        return "text" if path.suffix == ".md" else "jsonl"
