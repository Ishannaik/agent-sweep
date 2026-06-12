"""Core sources: ClaudeCode, Codex, OpenCode, Aider."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Iterator

from ..preflight import (
    AIDER_MARKERS,
    CLAUDE_CODE_MARKERS,
    CODEX_MARKERS,
    OPENCODE_MARKERS,
)
from ._base import JsonlSource, KeyPath, Source, _walk_json_with_base
from ._helpers import (
    _apply_json_file_redactions,
    _apply_plaintext_redactions,
    _iter_json_file_strings,
    _iter_plaintext_lines,
    _redact_sqlite_copy,
)


class ClaudeCodeSource(JsonlSource):
    """Claude Code CLI — per-session JSONL under ~/.claude/projects/."""

    name = "claude-code"
    display_name = "Claude Code"
    process_markers = CLAUDE_CODE_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".claude" / "projects"


class CodexSource(JsonlSource):
    """OpenAI Codex CLI — rollout JSONL under ~/.codex/sessions/YYYY/MM/DD/,
    plus history.jsonl and session_index.jsonl at the root."""

    name = "codex"
    display_name = "Codex"
    process_markers = CODEX_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".codex"


class OpenCodeSource(Source):
    """OpenCode (sst/opencode) — history stored in a SQLite database at
    ~/.local/share/opencode/opencode.db, or (legacy) as JSON files under
    ~/.local/share/opencode/storage/**/*.json.

    The XDG data dir resolves as follows:
    - Linux/macOS: $XDG_DATA_HOME if set, else ~/.local/share
    - Windows: $XDG_DATA_HOME if set, else %LOCALAPPDATA% if set,
      else ~/.local/share (xdg-basedir fallback)

    If the SQLite DB is present it is the primary source: text content from
    the ``part`` table (column ``content``) is scanned.  The redaction path
    updates the DB row in place.  If only the legacy JSON files exist they are
    scanned as ordinary JSON (not JSONL); each file is parsed as a dict and
    every string value is yielded.
    """

    name = "opencode"
    display_name = "OpenCode"
    process_markers = OPENCODE_MARKERS

    _SQLITE_SENTINEL = "__sqlite_row__"

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def _xdg_data_home(cls) -> Path:
        xdg = os.environ.get("XDG_DATA_HOME", "")
        if xdg:
            return Path(xdg)
        if sys.platform == "win32":
            local_app = os.environ.get("LOCALAPPDATA", "")
            if local_app:
                return Path(local_app)
        return Path.home() / ".local" / "share"

    @classmethod
    def default_root(cls) -> Path:
        return cls._xdg_data_home() / "opencode"

    def _db_path(self) -> Path:
        return self.root / "opencode.db"

    def _storage_dir(self) -> Path:
        return self.root / "storage"

    def _has_sqlite(self) -> bool:
        return self._db_path().is_file()

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        if self._has_sqlite():
            return [self._db_path()]
        storage = self._storage_dir()
        if not storage.exists():
            return []
        return sorted(p for p in storage.rglob("*.json") if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        if self._has_sqlite():
            yield self._db_path()
            return
        storage = self._storage_dir()
        if not storage.exists():
            return
        for p in storage.rglob("*.json"):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        if path == self._db_path():
            yield from self._iter_strings_sqlite(path)
        else:
            yield from _iter_json_file_strings(path)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        if path == self._db_path():
            return _redact_sqlite_copy(path, redactions, self._sqlite_text_columns)
        return _apply_json_file_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        # Only consulted for str returns, i.e. the legacy storage/*.json
        # files; the SQLite path returns source-validated bytes.
        return "json"

    def _iter_strings_sqlite(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
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
            "part": ["content"],
            "message": ["metadata", "metadata_part"],
            "session": ["title"],
            "session_input": ["content"],
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

class AiderSource(Source):
    """Aider CLI — per-repo Markdown history files named .aider.chat.history.md.

    Aider places one file in the root of each git repo (or CWD) the user works
    in. There is no central history directory, so we rglob from Path.home().
    """

    name = "aider"
    display_name = "Aider CLI"
    process_markers = AIDER_MARKERS

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        return Path.home()

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(
            p for p in self.root.rglob(".aider.chat.history.md") if p.is_file()
        )

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        for p in self.root.rglob(".aider.chat.history.md"):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        yield from _iter_plaintext_lines(path)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        return _apply_plaintext_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "text"
