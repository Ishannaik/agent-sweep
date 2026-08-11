"""Process-detection markers, including the Windows tasklist format."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import preflight  # noqa: E402


def test_detects_bare_image_name_from_tasklist(monkeypatch):
    # Windows `tasklist /FO CSV /NH` reports image names without a path.
    monkeypatch.setattr(
        preflight,
        "_list_process_cmdlines",
        lambda: ['"claude.exe","41360","Console","1","256,000 K"'],
    )
    running, marker = preflight.is_claude_code_running()
    assert running
    assert marker == "claude.exe"


def test_detects_npx_claude_code(monkeypatch):
    monkeypatch.setattr(
        preflight,
        "_list_process_cmdlines",
        lambda: ["node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"],
    )
    running, _ = preflight.is_claude_code_running()
    assert running


def test_no_false_positive_on_unrelated_processes(monkeypatch):
    monkeypatch.setattr(
        preflight,
        "_list_process_cmdlines",
        lambda: ['"chrome.exe","1234","Console","1","1,000 K"', "python -m pytest"],
    )
    running, marker = preflight.is_claude_code_running()
    assert not running
    assert marker == ""


def test_check_failure_returns_not_running(monkeypatch):
    monkeypatch.setattr(preflight, "_list_process_cmdlines", lambda: None)
    assert preflight.is_claude_code_running() == (False, "")
