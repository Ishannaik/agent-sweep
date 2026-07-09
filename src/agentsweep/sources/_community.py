"""Community sources: OpenClaw, Hermes Agent, Goose."""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path
from typing import Iterator

from ..preflight import (
    GOOSE_MARKERS,
    HERMES_MARKERS,
    OPENCLAW_MARKERS,
)
from ._base import JsonlSource, KeyPath, Source
from ._helpers import (
    _apply_jsonl_redactions,
    _iter_jsonl_strings,
    _redact_sqlite_copy,
    sqlite_sidecars,
)


class OpenClawSource(JsonlSource):
    """OpenClaw (openclaw/openclaw) — per-session JSONL under ~/.openclaw/.

    Override root with OPENCLAW_STATE_DIR env var.
    """

    name = "openclaw"
    display_name = "OpenClaw"
    process_markers = OPENCLAW_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        root = os.environ.get("OPENCLAW_STATE_DIR")
        if root:
            return Path(root)
        return Path.home() / ".openclaw"

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.rglob("*.jsonl") if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        for p in self.root.rglob("*.jsonl"):
            if p.is_file():
                yield p


class HermesSource(Source):
    """Hermes Agent (NousResearch/hermes-agent) — SQLite state.db.

    Primary store: ~/.hermes/state.db — messages table, content column.
    Windows: %LOCALAPPDATA%\\hermes\\state.db (fallback %APPDATA%\\hermes).
    Override: HERMES_HOME env var.
    """

    name = "hermes"
    display_name = "Hermes Agent"
    process_markers = HERMES_MARKERS

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        override = os.environ.get("HERMES_HOME")
        if override:
            return Path(override)
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or ""
            if base:
                return Path(base) / "hermes"
        return Path.home() / ".hermes"

    def _db(self) -> Path:
        return self.root / "state.db"

    def files(self) -> list[Path]:
        found = []
        if self._db().is_file():
            found.append(self._db())
        if self.root.exists():
            found.extend(sorted(p for p in self.root.rglob("*.jsonl") if p.is_file()))
        return found

    def iter_files(self) -> Iterator[Path]:
        if self._db().is_file():
            yield self._db()
        if self.root.exists():
            for p in self.root.rglob("*.jsonl"):
                if p.is_file():
                    yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        if path.suffix == ".jsonl":
            yield from _iter_jsonl_strings(path)
            return
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error:
            return
        try:
            for rowid, content in con.execute(
                "SELECT rowid, content FROM messages WHERE content IS NOT NULL"
            ):
                if isinstance(content, str) and content:
                    yield (max(rowid, 1), ["messages", rowid, "content"], content)
        except sqlite3.Error:
            pass
        finally:
            con.close()

    def _sqlite_text_columns(self, con: sqlite3.Connection) -> list[tuple[str, str]]:
        return [("messages", "content")]

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        if path.suffix == ".jsonl":
            return _apply_jsonl_redactions(path, redactions)
        return _redact_sqlite_copy(path, redactions, self._sqlite_text_columns)

    def sidecars(self, path: Path) -> list[Path]:
        if path.suffix == ".jsonl":
            return []
        return sqlite_sidecars(path)


class GooseSource(Source):
    """Goose (block/goose) — SQLite sessions.db + legacy per-session JSONL.

    Current (>=v1.10): ~/.local/share/goose/sessions/sessions.db (Linux/macOS)
                       %APPDATA%\\Block\\goose\\data\\sessions\\sessions.db (Windows)
    Legacy (<v1.10):  ~/.local/share/goose/sessions/*.jsonl
    Override: GOOSE_PATH_ROOT env var.
    """

    name = "goose"
    display_name = "Goose"
    process_markers = GOOSE_MARKERS

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        override = os.environ.get("GOOSE_PATH_ROOT")
        if override:
            return Path(override)
        if sys.platform == "win32":
            base = os.environ.get("APPDATA") or ""
            if base:
                return Path(base) / "Block" / "goose" / "data"
        return Path.home() / ".local" / "share" / "goose"

    def _sessions_dir(self) -> Path:
        return self.root / "sessions"

    def _db(self) -> Path:
        return self._sessions_dir() / "sessions.db"

    def files(self) -> list[Path]:
        found = []
        if self._db().is_file():
            found.append(self._db())
        sessions = self._sessions_dir()
        if sessions.exists():
            found.extend(sorted(p for p in sessions.glob("*.jsonl") if p.is_file()))
        return found

    def iter_files(self) -> Iterator[Path]:
        if self._db().is_file():
            yield self._db()
        sessions = self._sessions_dir()
        if sessions.exists():
            for p in sessions.glob("*.jsonl"):
                if p.is_file():
                    yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        if path.suffix == ".jsonl":
            yield from _iter_jsonl_strings(path)
            return
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error:
            return
        try:
            for rowid, content in con.execute(
                "SELECT rowid, content FROM messages WHERE content IS NOT NULL"
            ):
                if isinstance(content, str) and content:
                    yield (max(rowid, 1), ["messages", rowid, "content"], content)
        except sqlite3.Error:
            pass
        finally:
            con.close()

    def _sqlite_text_columns(self, con: sqlite3.Connection) -> list[tuple[str, str]]:
        return [("messages", "content")]

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        if path.suffix == ".jsonl":
            return _apply_jsonl_redactions(path, redactions)
        return _redact_sqlite_copy(path, redactions, self._sqlite_text_columns)

    def sidecars(self, path: Path) -> list[Path]:
        if path.suffix == ".jsonl":
            return []
        return sqlite_sidecars(path)


