from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from .redactor import SafetyError
from .preflight import (
    CLAUDE_CODE_MARKERS,
    CODEX_MARKERS,
    OPENCODE_MARKERS,
    CURSOR_MARKERS,
    WINDSURF_MARKERS,
    AIDER_MARKERS,
    CLINE_MARKERS,
    GEMINI_CLI_MARKERS,
    CONTINUE_MARKERS,
    GITHUB_COPILOT_MARKERS,
)

KeyPath = list  # list of str (dict keys) or int (list indices)


class Source(ABC):
    """Adapter for a specific AI coding agent's on-disk history format.

    To add a new source (Aider, Cursor, ...), subclass and implement the
    three abstract methods — or subclass JsonlSource if the agent stores
    plain JSONL. See CONTRIBUTING.md for the PR template.
    """

    name: str
    display_name: str
    root: Path
    # Substrings that identify the agent in a process listing; used by the
    # active-session safety gate before --fix.
    process_markers: tuple[str, ...] = ()

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
        that locates the string inside the file's structure (for JSONL: inside
        its parsed line). value is the raw string content.
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
        write. str content MUST preserve structure (line count, JSON
        validity, line endings) so the redactor's post-write validation
        passes; bytes content MUST be validated by the implementation
        (e.g. PRAGMA integrity_check) before it is returned.
        """


class JsonlSource(Source):
    """Shared implementation for agents that store history as JSONL files:
    every string value inside each line's parsed JSON is scanned, and
    redaction replaces values in the parsed structure before re-serializing."""

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
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield from _walk_json(obj, [], i)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        text = path.read_text(encoding="utf-8")
        # splitlines(keepends=True) preserves \r\n vs \n vs trailing-no-newline.
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
    plus history.jsonl and session_index.jsonl at the root.

    Rooted at ~/.codex: rglob('*.jsonl') picks up every transcript while
    structurally excluding auth.json (OAuth tokens, .json) and config.toml —
    files a redactor must never rewrite.
    """

    name = "codex"
    display_name = "Codex"
    process_markers = CODEX_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".codex"


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


def _redact_sqlite_copy(path: Path, redactions: list, columns_fn) -> bytes:
    """Apply SQLite redactions to a temp copy of `path` and return its bytes.

    The production database is never touched here — the pipeline writes the
    returned bytes back through redactor.safe_write, which owns the .bak
    backup, the atomic replace and the audit record (the same contract as
    text sources). Steps:

      1. Snapshot `path` into a sibling tempfile via sqlite's backup API
         (page-consistent, checkpoints any WAL into the copy).
      2. Run the UPDATEs against the copy with secure_delete on, then
         VACUUM, so the replaced plaintext cannot survive in freelist or
         page slack space — this is a secret-removal tool, "deleted but
         still on disk" defeats the point.
      3. Gate on PRAGMA integrity_check before returning the copy's bytes.

    `columns_fn(con)` returns the source's whitelisted (table, column)
    pairs; redactions targeting anything outside that whitelist are skipped.
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".redact")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        try:
            src_con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error as e:
            raise SafetyError(f"Cannot open {path} read-only: {e}") from e
        try:
            dst_con = sqlite3.connect(str(tmp))
            try:
                src_con.backup(dst_con)
                dst_con.execute("PRAGMA secure_delete = ON")
                allowed = set(columns_fn(dst_con))
                _apply_sqlite_updates(dst_con, redactions, allowed)
                dst_con.commit()
                dst_con.execute("VACUUM")
                row = dst_con.execute("PRAGMA integrity_check").fetchone()
                if row is None or row[0] != "ok":
                    raise SafetyError(
                        f"Redacted copy of {path.name} failed "
                        f"integrity_check; refusing to write")
            finally:
                dst_con.close()
        finally:
            src_con.close()
        return tmp.read_bytes()
    except sqlite3.Error as e:
        raise SafetyError(
            f"SQLite error while redacting {path.name}: {e}") from e
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _apply_sqlite_updates(
    con: sqlite3.Connection,
    redactions: list,
    allowed: set[tuple[str, str]],
) -> None:
    """Run redaction UPDATEs on `con`. Keypath encoding per SQLite row:
    [table, rowid, column] (+ JSON sub-path when the column holds JSON)."""
    for _line_num, kp, new_val in redactions:
        if len(kp) < 3:
            continue
        table, rowid, col = kp[0], kp[1], kp[2]
        if (table, col) not in allowed:
            continue
        sub_kp = kp[3:]
        if not sub_kp:
            # Direct column value
            con.execute(
                f"UPDATE {table} SET {col} = ? WHERE rowid = ?",  # noqa: S608 (whitelisted)
                (new_val, rowid),
            )
        else:
            # JSON-embedded value: read, patch, write back
            cur = con.execute(
                f"SELECT {col} FROM {table} WHERE rowid = ?",  # noqa: S608 (whitelisted)
                (rowid,),
            )
            row = cur.fetchone()
            if row is None:
                continue
            try:
                obj = json.loads(row[0])
            except (json.JSONDecodeError, TypeError):
                continue
            _set_by_path(obj, sub_kp, new_val)
            con.execute(
                f"UPDATE {table} SET {col} = ? WHERE rowid = ?",  # noqa: S608 (whitelisted)
                (json.dumps(obj, ensure_ascii=False), rowid),
            )


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

    # Sentinel path used in keypath to distinguish SQLite rows from JSON paths.
    _SQLITE_SENTINEL = "__sqlite_row__"

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def _xdg_data_home(cls) -> Path:
        """Return the XDG_DATA_HOME base directory for the current platform."""
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

    # --- SQLite helpers -------------------------------------------------

    def _db_path(self) -> Path:
        return self.root / "opencode.db"

    def _storage_dir(self) -> Path:
        return self.root / "storage"

    def _has_sqlite(self) -> bool:
        return self._db_path().is_file()

    # --- Source interface -----------------------------------------------

    def files(self) -> list[Path]:
        """Return the DB path (as a single-element list) if it exists, else
        every JSON file under the legacy storage/ directory."""
        if not self.root.exists():
            return []
        if self._has_sqlite():
            return [self._db_path()]
        storage = self._storage_dir()
        if not storage.exists():
            return []
        return sorted(p for p in storage.rglob("*.json") if p.is_file())

    def iter_files(self) -> Iterator[Path]:
        """Yield files as discovered (SQLite DB or legacy JSON files)."""
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
            yield from self._iter_strings_json(path)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        if path == self._db_path():
            return _redact_sqlite_copy(path, redactions,
                                       self._sqlite_text_columns)
        return self._apply_redactions_json(path, redactions)

    # --- SQLite scanning ------------------------------------------------

    def _iter_strings_sqlite(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        """Yield strings from the SQLite ``part`` and ``message`` tables.

        Keypath encoding for SQLite rows:
          [table_name, row_id, column_name]
        Line number is set to the rowid (1-based if rowid >= 1, else 1).
        """
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except (sqlite3.OperationalError, sqlite3.DatabaseError):
            return
        try:
            for table, col in self._sqlite_text_columns(con):
                try:
                    cur = con.execute(
                        f"SELECT rowid, {col} FROM {table}"  # noqa: S608 (controlled)
                    )
                except sqlite3.OperationalError:
                    continue
                for rowid, value in cur:
                    if not isinstance(value, str) or not value:
                        continue
                    # Try to expand JSON content stored as a string column
                    try:
                        obj = json.loads(value)
                        kp_base: KeyPath = [table, rowid, col]
                        yield from _walk_json_with_base(obj, kp_base, max(rowid, 1))
                    except (json.JSONDecodeError, TypeError):
                        yield (max(rowid, 1), [table, rowid, col], value)
        finally:
            con.close()

    def _sqlite_text_columns(self, con: sqlite3.Connection) -> list[tuple[str, str]]:
        """Return (table, column) pairs for TEXT columns in known tables."""
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

    # --- JSON (legacy) scanning/redaction --------------------------------

    def _iter_strings_json(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return
        yield from _walk_json(obj, [], 1)

    def _apply_redactions_json(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return text
        for _line_num, kp, new_val in redactions:
            _set_by_path(obj, kp, new_val)
        return json.dumps(obj, ensure_ascii=False, indent=2)


class _VSCodeSqliteSource(Source):
    """Shared base for VS Code-fork agents (Cursor, Windsurf) that store
    history in SQLite state.vscdb files under globalStorage and workspaceStorage.

    Subclasses must supply:
      - name / display_name / process_markers
      - default_root() -> Path  (the "User" directory, e.g. ~/.config/Cursor/User)
    """

    _SQLITE_SENTINEL = "__sqlite_row__"

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        raise NotImplementedError

    # ---- file discovery ---------------------------------------------------

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

    # ---- iter_strings -----------------------------------------------------

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
        """Return (table, column) pairs present in this database."""
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

    # ---- apply_redactions -------------------------------------------------

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> bytes:
        return _redact_sqlite_copy(path, redactions,
                                   self._sqlite_text_columns)


class CursorSource(_VSCodeSqliteSource):
    """Cursor IDE (Anysphere) — history in state.vscdb files under the Cursor
    User directory.  Two stores are scanned:

    - globalStorage/state.vscdb  — all-time conversation blobs (cursorDiskKV
      with ``bubbleId:*`` and ``composerData:*`` keys, plus ItemTable)
    - workspaceStorage/*/state.vscdb — per-workspace copies (same schema)

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

    def files(self) -> list[Path]:
        result: list[Path] = []
        if self.root.exists():
            result.extend(sorted(p for p in self.root.rglob("*.vscdb") if p.is_file()))
        transcripts_root = self._agent_transcripts_root()
        if transcripts_root.exists():
            result.extend(
                sorted(
                    p
                    for p in transcripts_root.rglob("*.jsonl")
                    if p.is_file()
                )
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
    as Cursor.  Both ItemTable (chat/cascade keys) and cursorDiskKV (agent/flow
    keys) are scanned.

    Additionally, Codeium memory markdown files under
    %USERPROFILE%\\.codeium\\windsurf\\memories\\ (Windows) or
    ~/.codeium/windsurf/memories/ (macOS/Linux) are scanned as plain-text.
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


class AiderSource(Source):
    """Aider CLI — per-repo Markdown history files named .aider.chat.history.md.

    Aider places one file in the root of each git repo (or CWD) the user works
    in.  There is no central history directory, so we rglob from Path.home()
    to find all instances on the machine.

    User turns are identified by the ``#### `` prefix; AI response lines have
    no prefix and are treated as plain text.  Both are scanned — the user lines
    are highest-priority (pasted API keys in prompts) but AI responses may echo
    keys back.
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
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        for i, line in enumerate(text.splitlines(), 1):
            if line.strip():
                yield (i, [i], line)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""
        lines = text.splitlines(keepends=True)
        by_line: dict[int, str] = {line_num: new_val for line_num, _kp, new_val in redactions}
        out: list[str] = []
        for i, line in enumerate(lines, 1):
            if i in by_line:
                ending = _line_ending(line)
                out.append(by_line[i] + ending)
            else:
                out.append(line)
        return "".join(out)


class ClineSource(Source):
    """Cline VS Code extension (saoudrizwan.claude-dev) — per-task JSON files.

    Each task directory under the globalStorage path for the extension holds an
    ``api_conversation_history.json`` file: a JSON array of message objects
    where ``content`` is either a plain string or a list of typed content
    blocks (text blocks: ``{type: "text", text: "..."}``).

    Paths scanned (all platforms use the VS Code globalStorage convention):
    - Windows: %APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\tasks\\*
    - macOS:   ~/Library/Application Support/Code/User/globalStorage/...
    - Linux:   ~/.config/Code/User/globalStorage/...
    """

    name = "cline"
    display_name = "Cline"
    process_markers = CLINE_MARKERS

    _TASK_GLOB = "tasks/*/api_conversation_history.json"

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def _vscode_user_dir(cls) -> Path:
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                return Path(appdata) / "Code" / "User"
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "Code" / "User"
        return Path(os.environ.get("XDG_CONFIG_HOME", "")) / "Code" / "User" if os.environ.get("XDG_CONFIG_HOME") else Path.home() / ".config" / "Code" / "User"

    @classmethod
    def default_root(cls) -> Path:
        return cls._vscode_user_dir() / "globalStorage" / "saoudrizwan.claude-dev"

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(
            p for p in self.root.glob(self._TASK_GLOB) if p.is_file()
        )

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        for p in self.root.glob(self._TASK_GLOB):
            if p.is_file():
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return
        yield from _walk_json(obj, [], 1)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return text
        for _line_num, kp, new_val in redactions:
            _set_by_path(obj, kp, new_val)
        return json.dumps(obj, ensure_ascii=False, indent=2)


class GeminiCliSource(JsonlSource):
    """Gemini CLI (Google) — session JSONL files under ~/.gemini/tmp/*/chats/.

    File layout:
      ~/.gemini/tmp/<project_slug>/chats/session-<date>-<id>.jsonl
      ~/.gemini/tmp/<project_slug>/chats/<parent_id>/session-*.jsonl  (subagents)

    Each JSONL line is one of: metadata record, user message record, gemini
    response record, or a patch/$set/$rewindTo control record.  Every string
    value in each line is walked and yielded — the key path is the JSON keypath
    within the parsed line object.

    The GEMINI_CLI_HOME env var overrides the home directory base.
    """

    name = "gemini-cli"
    display_name = "Gemini CLI"
    process_markers = GEMINI_CLI_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        gemini_home = os.environ.get("GEMINI_CLI_HOME", "")
        if gemini_home:
            return Path(gemini_home) / ".gemini"
        return Path.home() / ".gemini"

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        tmp = self.root / "tmp"
        if not tmp.exists():
            return []
        result = []
        for p in tmp.rglob("*.jsonl"):
            if p.is_file():
                result.append(p)
        for p in tmp.rglob("*.json"):
            if p.is_file() and "chats" in p.parts:
                result.append(p)
        return sorted(result)

    def iter_files(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        tmp = self.root / "tmp"
        if not tmp.exists():
            return
        for p in tmp.rglob("*.jsonl"):
            if p.is_file():
                yield p
        for p in tmp.rglob("*.json"):
            if p.is_file() and "chats" in p.parts:
                yield p


class ContinueSource(Source):
    """Continue VS Code / JetBrains extension (continuedev/continue) — session
    JSON files at ~/.continue/sessions/<uuid>.json.

    Each file is a JSON object with a ``history`` array.  Each history entry
    has a ``message`` object with ``role`` and ``content`` (string or list of
    typed content blocks with ``{type, text}`` items).

    All platforms use ~/.continue (Node.js os.homedir()) regardless of OS.
    """

    name = "continue-vscode"
    display_name = "Continue"
    process_markers = CONTINUE_MARKERS

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def default_root(cls) -> Path:
        return Path.home() / ".continue"

    def _sessions_dir(self) -> Path:
        return self.root / "sessions"

    def files(self) -> list[Path]:
        sessions = self._sessions_dir()
        if not sessions.exists():
            return []
        return sorted(
            p for p in sessions.glob("*.json")
            if p.is_file() and p.name != "sessions.json"
        )

    def iter_files(self) -> Iterator[Path]:
        sessions = self._sessions_dir()
        if not sessions.exists():
            return
        for p in sessions.glob("*.json"):
            if p.is_file() and p.name != "sessions.json":
                yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return
        yield from _walk_json(obj, [], 1)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return text
        for _line_num, kp, new_val in redactions:
            _set_by_path(obj, kp, new_val)
        return json.dumps(obj, ensure_ascii=False, indent=2)


class GitHubCopilotSource(Source):
    """GitHub Copilot Chat (VS Code) — session files under workspaceStorage.

    Two coexisting formats are scanned:
    - NEW (VS Code >= 1.109): workspaceStorage/<hash>/chatSessions/*.json and *.jsonl
    - LEGACY (VS Code < 1.109): workspaceStorage/<hash>/GitHub.copilot-chat/transcripts/*.jsonl
    - EMPTY WINDOW: globalStorage/emptyWindowChatSessions/*.json and *.jsonl

    JSON files are parsed as whole objects; JSONL files are parsed line-by-line.
    In both cases all string values in the parsed structure are yielded.
    """

    name = "github-copilot-chat"
    display_name = "GitHub Copilot Chat"
    process_markers = GITHUB_COPILOT_MARKERS

    def __init__(self, root: Path | None = None):
        self.root = root or self.default_root()

    @classmethod
    def _vscode_user_dir(cls) -> Path:
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                return Path(appdata) / "Code" / "User"
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "Code" / "User"
        xdg = os.environ.get("XDG_CONFIG_HOME", "")
        if xdg:
            return Path(xdg) / "Code" / "User"
        return Path.home() / ".config" / "Code" / "User"

    @classmethod
    def default_root(cls) -> Path:
        return cls._vscode_user_dir()

    def _workspace_storage(self) -> Path:
        return self.root / "workspaceStorage"

    def _global_storage(self) -> Path:
        return self.root / "globalStorage"

    def files(self) -> list[Path]:
        result: list[Path] = []
        ws = self._workspace_storage()
        if ws.exists():
            for p in ws.rglob("chatSessions/*.json"):
                if p.is_file():
                    result.append(p)
            for p in ws.rglob("chatSessions/*.jsonl"):
                if p.is_file():
                    result.append(p)
            for p in ws.rglob("GitHub.copilot-chat/transcripts/*.jsonl"):
                if p.is_file():
                    result.append(p)
        gs = self._global_storage()
        empty_win = gs / "emptyWindowChatSessions"
        if empty_win.exists():
            for p in empty_win.glob("*.json"):
                if p.is_file():
                    result.append(p)
            for p in empty_win.glob("*.jsonl"):
                if p.is_file():
                    result.append(p)
        return sorted(result)

    def iter_files(self) -> Iterator[Path]:
        ws = self._workspace_storage()
        if ws.exists():
            for p in ws.rglob("chatSessions/*.json"):
                if p.is_file():
                    yield p
            for p in ws.rglob("chatSessions/*.jsonl"):
                if p.is_file():
                    yield p
            for p in ws.rglob("GitHub.copilot-chat/transcripts/*.jsonl"):
                if p.is_file():
                    yield p
        gs = self._global_storage()
        empty_win = gs / "emptyWindowChatSessions"
        if empty_win.exists():
            for p in empty_win.glob("*.json"):
                if p.is_file():
                    yield p
            for p in empty_win.glob("*.jsonl"):
                if p.is_file():
                    yield p

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        if path.suffix == ".jsonl":
            yield from _iter_jsonl_strings(path)
        else:
            yield from _iter_json_file_strings(path)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        if path.suffix == ".jsonl":
            return _apply_jsonl_redactions(path, redactions)
        return _apply_json_file_redactions(path, redactions)


# ---------------------------------------------------------------------------
# Shared low-level helpers for new source types
# ---------------------------------------------------------------------------

def _iter_jsonl_strings(path: Path) -> Iterator[tuple[int, KeyPath, str]]:
    """Yield (line_num, keypath, value) for every string in a JSONL file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        yield from _walk_json(obj, [], i)


def _apply_jsonl_redactions(
    path: Path,
    redactions: list[tuple[int, KeyPath, str]],
) -> str:
    """Apply redactions to a JSONL file, preserving line count and endings."""
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


def _iter_json_file_strings(path: Path) -> Iterator[tuple[int, KeyPath, str]]:
    """Yield all string values from a whole-file JSON object/array."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return
    yield from _walk_json(obj, [], 1)


def _apply_json_file_redactions(
    path: Path,
    redactions: list[tuple[int, KeyPath, str]],
) -> str:
    """Apply redactions to a whole-file JSON, returning pretty-printed JSON."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return text
    for _line_num, kp, new_val in redactions:
        _set_by_path(obj, kp, new_val)
    return json.dumps(obj, ensure_ascii=False, indent=2)


def _iter_plaintext_lines(path: Path) -> Iterator[tuple[int, KeyPath, str]]:
    """Yield (line_num, [line_num], line_text) for every non-empty line."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip():
            yield (i, [i], line)


def _apply_plaintext_redactions(
    path: Path,
    redactions: list[tuple[int, KeyPath, str]],
) -> str:
    """Apply line-level redactions to a plain-text file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    lines = text.splitlines(keepends=True)
    by_line: dict[int, str] = {line_num: new_val for line_num, _kp, new_val in redactions}
    out: list[str] = []
    for i, line in enumerate(lines, 1):
        if i in by_line:
            ending = _line_ending(line)
            out.append(by_line[i] + ending)
        else:
            out.append(line)
    return "".join(out)


SOURCES: dict[str, type[Source]] = {
    "claude-code": ClaudeCodeSource,
    "codex": CodexSource,
    "opencode": OpenCodeSource,
    "cursor": CursorSource,
    "windsurf": WindsurfSource,
    "aider": AiderSource,
    "cline": ClineSource,
    "gemini-cli": GeminiCliSource,
    "continue-vscode": ContinueSource,
    "github-copilot-chat": GitHubCopilotSource,
}
