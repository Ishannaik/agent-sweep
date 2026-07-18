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
    LLM_MARKERS,
    OPENCLAW_MARKERS,
)
from ._base import JsonlSource, KeyPath, Source
from ._helpers import (
    _apply_jsonl_redactions,
    _iter_jsonl_strings,
    _quote_ident,
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


class LlmSource(Source):
    """Datasette `llm` CLI (simonw/llm) — prompt/response history in logs.db.

    The database lives in ``llm``'s user directory, which the tool resolves as
    ``click.get_app_dir("io.datasette.llm")`` (honouring ``LLM_USER_PATH``):

      - Linux/other: ``$XDG_CONFIG_HOME/io.datasette.llm`` (else ``~/.config/…``)
      - macOS:       ``~/Library/Application Support/io.datasette.llm``
      - Windows:     ``%APPDATA%\\io.datasette.llm``

    The store is a single SQLite file, ``logs.db``. Scanned columns are the
    free text a user, model, or tool can put a secret into: ``responses``
    prompt/system/response/reasoning, ``fragments`` content/source (files and
    URLs attached with ``llm -f``), ``conversations.name``, and — for llm's
    tool calls (>= 0.26) — ``tool_calls.arguments``, ``tool_results``
    output/exception, and ``schemas.content``. The parallel JSON columns
    (``prompt_json`` / ``response_json`` / ``options_json``) are deliberately
    skipped — ``llm`` condenses fragment and response text out of them into
    ``f:``/``r:`` placeholders, so they yield duplicate hits, not new coverage.

    Redaction goes through the shared SQLite copy-and-rewrite path. ``logs.db``
    also keeps a full-text index (``responses_fts``, an FTS5 *external-content*
    table) synced by ``AFTER UPDATE``/``DELETE`` triggers, so a normal UPDATE
    removes the secret's terms from the index too; ``secure_delete`` + ``VACUUM``
    (both inside ``_redact_sqlite_copy``) then scrub the freed index pages.
    Verified against llm 0.31.1: after a redaction no plaintext survives in the
    FTS shadow tables and the token is no longer MATCH-able.
    """

    name = "llm"
    display_name = "llm (Datasette)"
    process_markers = LLM_MARKERS

    # Whitelisted table -> candidate text columns. Only columns that actually
    # exist are scanned/redacted, so older logs.db schemas (no ``system``, no
    # ``fragments`` table) still work. A known table that exists but has lost
    # ALL of its expected columns raises rather than silently scanning nothing
    # — the same false-all-clear guard OpenCode added for issue #14.
    _KNOWN_COLUMNS: dict[str, list[str]] = {
        "responses": ["prompt", "system", "response", "reasoning"],
        "fragments": ["content", "source"],
        "conversations": ["name"],
        # llm >= 0.26 tool support: a tool that reads a secret (e.g. cats a
        # .env) lands it here, not in responses. Absent tables/columns are
        # skipped, so older logs.db still work (see the drift guard below).
        "tool_calls": ["arguments"],
        "tool_results": ["output", "exception"],
        "schemas": ["content"],
    }

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        override = os.environ.get("LLM_USER_PATH")
        if override:
            return Path(override)
        return cls._app_dir("io.datasette.llm")

    @staticmethod
    def _app_dir(app: str) -> Path:
        """Replicate ``click.get_app_dir(app, roaming=True)`` without taking a
        dependency on click — this is how ``llm.user_dir()`` resolves the dir."""
        if sys.platform == "win32":
            base = os.environ.get("APPDATA")
            if base:
                return Path(base) / app
            return Path.home() / "AppData" / "Roaming" / app
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / app
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg else Path.home() / ".config"
        return base / app

    def _db(self) -> Path:
        return self.root / "logs.db"

    def files(self) -> list[Path]:
        return [self._db()] if self._db().is_file() else []

    def iter_files(self) -> Iterator[Path]:
        if self._db().is_file():
            yield self._db()

    def is_detected(self) -> bool:
        return self._db().is_file()

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error:
            return
        try:
            for table, col in self._sqlite_text_columns(con):
                # (table, col) existence is verified in _sqlite_text_columns via
                # PRAGMA table_info, so a bad-column OperationalError here would
                # be a real bug, not an expected miss — let it surface.
                for rowid, value in con.execute(
                    f"SELECT rowid, {_quote_ident(col)} FROM {_quote_ident(table)}"  # nosec B608 # table/col are SQL-escaped via _quote_ident(), not raw interpolation; bandit can't see through the helper
                ):
                    if isinstance(value, str) and value:
                        yield (max(rowid, 1), [table, rowid, col], value)
        finally:
            con.close()

    def _sqlite_text_columns(
        self, con: sqlite3.Connection
    ) -> list[tuple[str, str]]:
        try:
            tables = {
                row[0]
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        except sqlite3.Error:
            return []
        pairs: list[tuple[str, str]] = []
        for table, cols in self._KNOWN_COLUMNS.items():
            if table not in tables:
                continue
            actual = {row[1] for row in con.execute(f"PRAGMA table_info({_quote_ident(table)})")}
            present = [c for c in cols if c in actual]
            if not present:
                raise RuntimeError(
                    f"llm schema drift: table {table!r} has none of the "
                    f"expected text columns {cols!r}; llm changed its schema "
                    "and this scan would silently miss it. Please file an issue "
                    "at https://github.com/Ishannaik/agent-sweep/issues"
                )
            pairs.extend((table, c) for c in present)
        return pairs

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        return _redact_sqlite_copy(path, redactions, self._sqlite_text_columns)

    def sidecars(self, path: Path) -> list[Path]:
        return sqlite_sidecars(path)


