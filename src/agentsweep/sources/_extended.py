"""Extended sources: Cline, GeminiCLI, Continue, GitHub Copilot Chat."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Iterator

from ..preflight import (
    CLINE_MARKERS,
    CONTINUE_MARKERS,
    GEMINI_CLI_MARKERS,
    GITHUB_COPILOT_MARKERS,
    KILO_CODE_MARKERS,
    OPEN_INTERPRETER_MARKERS,
    ROO_CODE_MARKERS,
)
from ._base import JsonlSource, KeyPath, Source, _walk_json
from ._helpers import (
    _apply_json_file_redactions,
    _apply_jsonl_redactions,
    _iter_json_file_strings,
    _iter_jsonl_strings,
)


class ClineSource(Source):
    """Cline VS Code extension (saoudrizwan.claude-dev) — per-task JSON files.

    Each task directory under the globalStorage path for the extension holds an
    ``api_conversation_history.json`` file: a JSON array of message objects
    where ``content`` is either a plain string or a list of typed content
    blocks (text blocks: ``{type: "text", text: "..."}``).

    Paths scanned:
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
        xdg = os.environ.get("XDG_CONFIG_HOME", "")
        if xdg:
            return Path(xdg) / "Code" / "User"
        return Path.home() / ".config" / "Code" / "User"

    @classmethod
    def default_root(cls) -> Path:
        return cls._vscode_user_dir() / "globalStorage" / "saoudrizwan.claude-dev"

    def files(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.glob(self._TASK_GLOB) if p.is_file())

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
        return _apply_json_file_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "json"


class KiloCodeSource(ClineSource):
    """Kilo Code (kilocode.kilo-code) — a Cline/Roo fork that stores the
    identical per-task ``api_conversation_history.json`` layout under its own
    globalStorage directory. Only the extension dir differs from Cline, so all
    scan/redact logic is inherited.
    """

    name = "kilo-code"
    display_name = "Kilo Code"
    process_markers = KILO_CODE_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        return cls._vscode_user_dir() / "globalStorage" / "kilocode.kilo-code"


class RooCodeSource(ClineSource):
    """Roo Code (RooVeterinaryInc.roo-cline) — a Cline fork with the identical
    per-task ``api_conversation_history.json`` layout under its own
    globalStorage directory. Scan/redact logic is inherited from Cline.
    """

    name = "roo-code"
    display_name = "Roo Code"
    process_markers = ROO_CODE_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        return cls._vscode_user_dir() / "globalStorage" / "rooveterinaryinc.roo-cline"


class GeminiCliSource(JsonlSource):
    """Gemini CLI (Google) — session JSONL files under ~/.gemini/tmp/*/chats/.

    File layout:
      ~/.gemini/tmp/<project_slug>/chats/session-<date>-<id>.jsonl
      ~/.gemini/tmp/<project_slug>/chats/<parent_id>/session-*.jsonl  (subagents)
      ~/.gemini/tmp/<project_slug>/chats/*.json  (checkpoints, whole-file JSON)

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

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        # Checkpoint *.json files are one pretty-printed document — the
        # line-by-line JSONL parser would silently yield nothing for them.
        if path.suffix == ".json":
            yield from _iter_json_file_strings(path)
        else:
            yield from super().iter_strings(path)

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str:
        if path.suffix == ".json":
            return _apply_json_file_redactions(path, redactions)
        return super().apply_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "json" if path.suffix == ".json" else "jsonl"


class ContinueSource(Source):
    """Continue VS Code / JetBrains extension (continuedev/continue) — session
    JSON files at ~/.continue/sessions/<uuid>.json.

    Each file is a JSON object with a ``history`` array. All platforms use
    ~/.continue (Node.js os.homedir()) regardless of OS.
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
            p
            for p in sessions.glob("*.json")
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
        return _apply_json_file_redactions(path, redactions)

    def content_format(self, path: Path) -> str:
        return "json"


class OpenInterpreterSource(ContinueSource):
    """Open Interpreter — whole-file JSON conversations under the platform
    config dir: ``<user_config_dir>/open-interpreter/conversations/*.json``.

    Reuses ContinueSource's whole-file JSON walk and redaction; only the root
    and the history subdirectory ("conversations" rather than "sessions")
    differ.
    """

    name = "open-interpreter"
    display_name = "Open Interpreter"
    process_markers = OPEN_INTERPRETER_MARKERS

    @classmethod
    def default_root(cls) -> Path:
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA", "")
            if base:
                return Path(base) / "open-interpreter"
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "open-interpreter"
        xdg = os.environ.get("XDG_CONFIG_HOME", "")
        if xdg:
            return Path(xdg) / "open-interpreter"
        return Path.home() / ".config" / "open-interpreter"

    def _sessions_dir(self) -> Path:
        return self.root / "conversations"


class GitHubCopilotSource(Source):
    """GitHub Copilot Chat (VS Code) — session files under workspaceStorage.

    Two coexisting formats are scanned:
    - NEW (VS Code >= 1.109): workspaceStorage/<hash>/chatSessions/*.json and *.jsonl
    - LEGACY (VS Code < 1.109): workspaceStorage/<hash>/GitHub.copilot-chat/transcripts/*.jsonl
    - EMPTY WINDOW: globalStorage/emptyWindowChatSessions/*.json and *.jsonl

    JSON files are parsed as whole objects; JSONL files are parsed line-by-line.
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

    def content_format(self, path: Path) -> str:
        return "jsonl" if path.suffix == ".jsonl" else "json"
