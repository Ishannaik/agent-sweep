"""Additional agent sources added after v0.1.6.

Grouped by storage shape:
  - _GenericSqliteSource: a single .db whose schema we don't hard-code — every
    text column of every table is scanned (Warp, Grok CLI, Kiro CLI, Zed).
  - whole-file JSON (Codebuff, Plandex) and Gemini-style checkpoints (Qwen).
  - VS Code SQLite forks (Trae, Void) and a Cline fork (PearAI).
  - line-oriented text/JSONL (Junie, Mentat, JetBrains AI Assistant XML).

A source whose path does not exist simply yields nothing (files() == []), so an
imperfectly-located store is a harmless no-op rather than a crash.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Iterator

from ..preflight import (
    CODEBUFF_MARKERS,
    GROK_CLI_MARKERS,
    JETBRAINS_AI_MARKERS,
    JUNIE_MARKERS,
    KIRO_CLI_MARKERS,
    MENTAT_MARKERS,
    PEARAI_MARKERS,
    PLANDEX_MARKERS,
    QWEN_CODE_MARKERS,
    TRAE_MARKERS,
    VOID_MARKERS,
    WARP_MARKERS,
    ZED_MARKERS,
)
from ._base import KeyPath, Source, _walk_json_with_base
from ._extended import ClineSource, GeminiCliSource
from ._helpers import (
    _apply_json_file_redactions,
    _apply_jsonl_redactions,
    _apply_plaintext_redactions,
    _iter_json_file_strings,
    _iter_jsonl_strings,
    _iter_plaintext_lines,
    _redact_sqlite_copy,
    sqlite_sidecars,
)
from ._vscode import _VSCodeSqliteSource


# ── shared helpers ────────────────────────────────────────────────────────────

def _vscode_appdata_base() -> Path:
    """The per-OS base dir VS Code-fork editors put their data folder under."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            return Path(appdata)
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support"
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    return Path(xdg) if xdg else (Path.home() / ".config")


def _all_table_columns(con: sqlite3.Connection) -> list[tuple[str, str]]:
    """Every (table, column) in the db except sqlite internals — we don't know
    each agent's schema, so scan them all and let the str check filter."""
    pairs: list[tuple[str, str]] = []
    try:
        tables = [
            r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        ]
    except sqlite3.Error:
        return pairs
    for table in tables:
        try:
            cols = con.execute(f'PRAGMA table_info("{table}")').fetchall()
        except sqlite3.Error:
            continue
        for col in cols:
            pairs.append((table, col[1]))
    return pairs


def _iter_sqlite_all_columns(path: Path, columns_fn) -> Iterator[tuple[int, KeyPath, str]]:
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return
    try:
        for table, col in columns_fn(con):
            try:
                cur = con.execute(f'SELECT rowid, "{col}" FROM "{table}"')
            except sqlite3.Error:
                continue  # WITHOUT ROWID tables, virtual tables, etc.
            for rowid, value in cur:
                if not isinstance(value, str) or not value:
                    continue  # NULL / numeric / BLOB columns are skipped
                try:
                    obj = json.loads(value)
                    yield from _walk_json_with_base(
                        obj, [table, rowid, col], max(rowid, 1))
                except (json.JSONDecodeError, TypeError):
                    yield (max(rowid, 1), [table, rowid, col], value)
    finally:
        con.close()


class _GenericSqliteSource(Source):
    """Base for agents whose history is one SQLite db with a schema we don't
    hard-code. Scans every text column of every table read-only; redaction
    UPDATEs the same cells via the copy-and-verify path."""

    experimental = True

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        raise NotImplementedError

    def _db(self) -> Path:
        raise NotImplementedError

    def files(self) -> list[Path]:
        db = self._db()
        return [db] if db.is_file() else []

    def iter_files(self) -> Iterator[Path]:
        db = self._db()
        if db.is_file():
            yield db

    def _sqlite_text_columns(self, con: sqlite3.Connection) -> list[tuple[str, str]]:
        return _all_table_columns(con)

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        yield from _iter_sqlite_all_columns(path, self._sqlite_text_columns)

    def apply_redactions(self, path: Path, redactions: list) -> bytes:
        return _redact_sqlite_copy(path, redactions, self._sqlite_text_columns)

    def sidecars(self, path: Path) -> list[Path]:
        return sqlite_sidecars(path)


# ── SQLite agents ─────────────────────────────────────────────────────────────

class WarpSource(_GenericSqliteSource):
    """Warp terminal — single warp.sqlite (agent_conversations, ai_queries,
    blocks). Cloud sync is opt-in, so the local db is the default store."""

    name = "warp"
    display_name = "Warp"
    process_markers = WARP_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA", "")
            if base:
                return Path(base) / "warp" / "Warp" / "data"
        elif sys.platform == "darwin":
            return (Path.home() / "Library" / "Application Support"
                    / "dev.warp.Warp-Stable")
        state = os.environ.get("XDG_STATE_HOME") or str(
            Path.home() / ".local" / "state")
        return Path(state) / "warp-terminal"

    def _db(self) -> Path:
        return self.root / "warp.sqlite"


class GrokCliSource(_GenericSqliteSource):
    """Grok CLI (superagent-ai/grok-cli) — ~/.grok/grok.db (messages table)."""

    name = "grok-cli"
    display_name = "Grok CLI"
    process_markers = GROK_CLI_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".grok"

    def _db(self) -> Path:
        return self.root / "grok.db"


class ZedSource(_GenericSqliteSource):
    """Zed editor agent threads — <data>/threads/threads.db. The `summary`
    column is plaintext (scanned); the `data` column is a zstd-compressed BLOB,
    which the generic scanner skips (bytes, not str), so coverage is thread
    titles/summaries until a zstd decode path is added."""

    name = "zed"
    display_name = "Zed"
    process_markers = ZED_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA", "")
            if base:
                return Path(base) / "Zed"
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "Zed"
        data = os.environ.get("XDG_DATA_HOME") or str(
            Path.home() / ".local" / "share")
        return Path(data) / "zed"

    def _db(self) -> Path:
        return self.root / "threads" / "threads.db"


class KiroCliSource(_GenericSqliteSource):
    """Kiro CLI (AWS) — a SQLite db under ~/.kiro/ auto-saved every turn. The
    db filename isn't public, so every *.db under the root is scanned."""

    name = "kiro-cli"
    display_name = "Kiro CLI"
    process_markers = KIRO_CLI_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".kiro"

    def _db(self) -> Path:  # unused; files() globs instead
        return self.root / "kiro.db"

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.rglob("*.db") if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        for p in self.root.rglob("*.db"):
            if p.is_file():
                yield p


# ── whole-file JSON agents ────────────────────────────────────────────────────

class CodebuffSource(Source):
    """Codebuff (formerly Manicode) — per-chat whole-file JSON at
    ~/.config/manicode/projects/<project>/chats/<chatId>/chat-messages.json
    on every OS (Node CLI uses ~/.config, not %APPDATA%)."""

    name = "codebuff"
    display_name = "Codebuff"
    process_markers = CODEBUFF_MARKERS
    experimental = True

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".config" / "manicode"

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.rglob("chat-messages.json")
                      if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        for p in self.root.rglob("chat-messages.json"):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        yield from _iter_json_file_strings(path)

    def apply_redactions(self, path: Path, redactions: list) -> str:
        return _apply_json_file_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "json"


class PlandexSource(Source):
    """Plandex (self-hosted) — conversation messages as one JSON file each under
    <base>/orgs/<org>/plans/<plan>/conversation/*.json. Base is $PLANDEX_BASE_DIR
    or $HOME/plandex-server (the local self-host default)."""

    name = "plandex"
    display_name = "Plandex"
    process_markers = PLANDEX_MARKERS
    experimental = True

    _GLOB = "orgs/*/plans/*/conversation/*.json"

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        override = os.environ.get("PLANDEX_BASE_DIR")
        if override:
            return Path(override)
        return Path.home() / "plandex-server"

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.glob(self._GLOB) if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        for p in self.root.glob(self._GLOB):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        yield from _iter_json_file_strings(path)

    def apply_redactions(self, path: Path, redactions: list) -> str:
        return _apply_json_file_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "json"


class QwenCodeSource(GeminiCliSource):
    """Qwen Code (Alibaba) — a Gemini CLI fork; saved conversations are
    checkpoint-<tag>.json under ~/.qwen/tmp/<hash>/. Reuses Gemini's whole-file
    JSON handling, but globs the checkpoints directly (they aren't under a
    chats/ subdir like Gemini's)."""

    name = "qwen-code"
    display_name = "Qwen Code"
    process_markers = QWEN_CODE_MARKERS
    experimental = True

    @classmethod
    def default_root(cls) -> Path:
        override = os.environ.get("QWEN_CODE_HOME", "")
        if override:
            return Path(override) / ".qwen"
        return Path.home() / ".qwen"

    def files(self) -> list[Path]:
        tmp = self.root / "tmp"
        if not tmp.exists():
            return []
        return sorted(p for p in tmp.rglob("*.json") if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        tmp = self.root / "tmp"
        if not tmp.exists():
            return
        for p in tmp.rglob("*.json"):
            if p.is_file():
                yield p


class PearAiSource(ClineSource):
    """PearAI — its Roo/Cline fork (PearAI.pearai-roo-cline) writes the same
    per-task api_conversation_history.json layout as Cline, under the PearAI
    editor's globalStorage."""

    name = "pearai"
    display_name = "PearAI"
    process_markers = PEARAI_MARKERS
    experimental = True

    @classmethod
    def default_root(cls) -> Path:
        return (_vscode_appdata_base() / "PearAI" / "User" / "globalStorage"
                / "PearAI.pearai-roo-cline")


# ── VS Code SQLite forks ──────────────────────────────────────────────────────

class TraeSource(_VSCodeSqliteSource):
    """Trae (ByteDance) — a VS Code fork; chat lives in its own state.vscdb
    files under the Trae User dir, scanned with the shared VS Code SQLite walk."""

    name = "trae"
    display_name = "Trae"
    process_markers = TRAE_MARKERS
    experimental = True

    @classmethod
    def default_root(cls) -> Path:
        return _vscode_appdata_base() / "Trae" / "User"


class VoidSource(_VSCodeSqliteSource):
    """Void editor — a VS Code fork; chat threads are JSON under the
    void.chatThreadStorageII key in the application state.vscdb (ItemTable),
    which the shared VS Code SQLite walk picks up."""

    name = "void"
    display_name = "Void"
    process_markers = VOID_MARKERS
    experimental = True

    @classmethod
    def default_root(cls) -> Path:
        return _vscode_appdata_base() / "Void" / "User"


# ── line-oriented text / JSONL agents ─────────────────────────────────────────

class JunieSource(Source):
    """JetBrains Junie CLI — per-session files under ~/.junie/sessions/. The
    on-disk format (json vs jsonl) isn't documented, so both are handled."""

    name = "junie"
    display_name = "Junie"
    process_markers = JUNIE_MARKERS
    experimental = True

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".junie"

    def _sessions_dir(self) -> Path:
        return self.root / "sessions"

    def files(self) -> list[Path]:
        d = self._sessions_dir()
        if not d.exists():
            return []
        return sorted(p for p in d.rglob("*")
                      if p.is_file() and p.suffix in (".json", ".jsonl"))

    def iter_files(self) -> Iterator[Path]:
        d = self._sessions_dir()
        if not d.exists():
            return
        for p in d.rglob("*"):
            if p.is_file() and p.suffix in (".json", ".jsonl"):
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        if path.suffix == ".jsonl":
            yield from _iter_jsonl_strings(path)
        else:
            yield from _iter_json_file_strings(path)

    def apply_redactions(self, path: Path, redactions: list) -> str:
        if path.suffix == ".jsonl":
            return _apply_jsonl_redactions(path, redactions)
        return _apply_json_file_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "jsonl" if path.suffix == ".jsonl" else "json"


class MentatSource(Source):
    """Mentat (legacy CLI) — transcripts at ~/.mentat/logs/transcript_*.log,
    one JSON object per line. Scanned as plain text lines so the occasional
    non-JSON line never blocks a redaction."""

    name = "mentat"
    display_name = "Mentat"
    process_markers = MENTAT_MARKERS
    experimental = True

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".mentat"

    def _logs_dir(self) -> Path:
        return self.root / "logs"

    def files(self) -> list[Path]:
        d = self._logs_dir()
        if not d.exists():
            return []
        return sorted(p for p in d.glob("transcript_*.log") if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        d = self._logs_dir()
        if not d.exists():
            return
        for p in d.glob("transcript_*.log"):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        yield from _iter_plaintext_lines(path)

    def apply_redactions(self, path: Path, redactions: list) -> str:
        return _apply_plaintext_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "text"


class JetBrainsAiSource(Source):
    """JetBrains AI Assistant — per-project chat history in
    <config>/JetBrains/<product><ver>/workspace/<id>.xml inside
    <component name="ChatSessionStateTemp">. Scanned and redacted as plain text
    lines, which preserves the surrounding XML structure (line-count stable)."""

    name = "jetbrains-ai"
    display_name = "JetBrains AI Assistant"
    process_markers = JETBRAINS_AI_MARKERS
    experimental = True

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                return Path(appdata) / "JetBrains"
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "JetBrains"
        return Path.home() / ".config" / "JetBrains"

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.glob("*/workspace/*.xml")
                      if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        for p in self.root.glob("*/workspace/*.xml"):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        yield from _iter_plaintext_lines(path)

    def apply_redactions(self, path: Path, redactions: list) -> str:
        return _apply_plaintext_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "text"
