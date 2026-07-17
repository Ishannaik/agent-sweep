"""CRLF / Windows line-ending round-trip coverage for the redaction write path.

The write path promises byte-level structure preservation: line count, JSON
validity, and the exact line-ending byte sequence of every line. Agent history
files written on Windows can carry \r\n (and a final line with no trailing
newline), so each fixture variant must survive scan -> redact -> undo
byte-identically outside the redacted spans.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline  # noqa: E402
from agentsweep.cli import main  # noqa: E402

AWS_KEY = b"AKIAIOSFODNN7EXAMPLE"
MARKER = b"[REDACTED:aws-access-key]"

_LINE_WITH_SECRET = b'{"type":"user","text":"key=AKIAIOSFODNN7EXAMPLE"}'
_LINE_PLAIN = b'{"type":"assistant","text":"hello"}'

VARIANTS = {
    "lf": _LINE_WITH_SECRET + b"\n" + _LINE_PLAIN + b"\n",
    "crlf": _LINE_WITH_SECRET + b"\r\n" + _LINE_PLAIN + b"\r\n",
    "mixed_no_final_newline": (
        _LINE_PLAIN + b"\r\n" + _LINE_PLAIN + b"\n" + _LINE_WITH_SECRET
    ),
}


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Keep the audit log (~/.agentsweep/audit.jsonl) inside tmp_path."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture(autouse=True)
def _no_running_agent(monkeypatch):
    monkeypatch.setattr(pipeline, "is_agent_running",
                        lambda markers: (False, ""))


def _endings(data: bytes) -> list[bytes]:
    """The file's line-ending byte sequences, in order (\r\n before \n)."""
    return re.findall(rb"\r\n|\r|\n", data)


@pytest.mark.parametrize("variant", VARIANTS)
def test_redact_preserves_line_ending_bytes(tmp_path, variant):
    root = tmp_path / "projects"
    root.mkdir()
    session = root / "session.jsonl"
    original = VARIANTS[variant]
    session.write_bytes(original)

    code = main(["--source", "claude-code", "--root", str(root),
                 "--fix", "--force"])
    assert code == 0

    redacted = session.read_bytes()
    assert AWS_KEY not in redacted
    assert MARKER in redacted
    assert len(redacted.splitlines()) == len(original.splitlines())
    assert _endings(redacted) == _endings(original)


@pytest.mark.parametrize("variant", VARIANTS)
def test_undo_restores_original_bytes(tmp_path, variant):
    root = tmp_path / "projects"
    root.mkdir()
    session = root / "session.jsonl"
    original = VARIANTS[variant]
    session.write_bytes(original)

    assert main(["--source", "claude-code", "--root", str(root),
                 "--fix", "--force"]) == 0
    backup = session.with_name(session.name + ".bak")
    assert backup.read_bytes() == original

    assert main(["undo", "--source", "claude-code", "--root", str(root)]) == 0
    assert session.read_bytes() == original
    assert not backup.exists()
