"""Round-trip --fix tests for the agent sources added after v0.1.5:

- Kilo Code and Roo Code: Cline-family forks with the identical per-task
  api_conversation_history.json layout (scan/redact inherited from ClineSource).
- Open Interpreter: whole-file JSON conversations (inherited from ContinueSource),
  rooted at the platform config dir with a 'conversations' subdir.

Each test detects a synthetic secret end-to-end and confirms redaction removes
it while keeping the file valid and backing it up.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.pipeline import _redact_all, _scan_file  # noqa: E402
from agentsweep.sources import (  # noqa: E402
    KiloCodeSource,
    OpenInterpreterSource,
    RooCodeSource,
)

SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example access key id


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def _scan(source, f: Path):
    _, items, _, _, _ = _scan_file(source, f, ignores=None)
    assert items, "fixture secret should be detected"
    return {f: items}


def _cline_task(root: Path) -> Path:
    """A Cline/Kilo/Roo per-task api_conversation_history.json with a secret."""
    task = root / "tasks" / "20260613-demo"
    task.mkdir(parents=True)
    f = task / "api_conversation_history.json"
    f.write_text(
        json.dumps(
            [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": f"use {SECRET} for s3"}],
                }
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    return f


def _round_trip(source, f: Path) -> str:
    rows, errors, _ = _redact_all(source, _scan(source, f), backup=True, force=True)
    assert errors == 0
    assert rows[0][0] == "ok"
    after = f.read_text(encoding="utf-8")
    assert SECRET not in after
    json.loads(after)  # still valid JSON
    assert f.with_name(f.name + ".bak").exists()
    return after


def test_kilo_code_round_trip(tmp_path: Path) -> None:
    root = tmp_path / "kilo"
    f = _cline_task(root)
    source = KiloCodeSource(root=root)
    assert f in source.files()
    _round_trip(source, f)


def test_roo_code_round_trip(tmp_path: Path) -> None:
    root = tmp_path / "roo"
    f = _cline_task(root)
    source = RooCodeSource(root=root)
    assert f in source.files()
    _round_trip(source, f)


def test_open_interpreter_round_trip(tmp_path: Path) -> None:
    root = tmp_path / "oi"
    conv = root / "conversations"
    conv.mkdir(parents=True)
    f = conv / "chat-2026-06-13.json"
    f.write_text(
        json.dumps([{"role": "user", "content": f"my key is {SECRET}"}], indent=2),
        encoding="utf-8",
    )
    source = OpenInterpreterSource(root=root)
    assert f in source.files()
    _round_trip(source, f)


def test_new_sources_have_distinct_default_roots() -> None:
    # Each subclass must point at its OWN extension/config dir, not Cline's.
    assert "kilocode.kilo-code" in str(KiloCodeSource().default_root())
    assert "rooveterinaryinc.roo-cline" in str(RooCodeSource().default_root())
    assert "open-interpreter" in str(OpenInterpreterSource().default_root())


def test_new_sources_registered() -> None:
    from agentsweep.sources import SOURCES

    for slug in ("kilo-code", "roo-code", "open-interpreter"):
        assert slug in SOURCES
