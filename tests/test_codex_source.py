"""Codex CLI source adapter: discovery, scanning, redaction, gates."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline, preflight  # noqa: E402
from agentsweep.cli import main  # noqa: E402
from agentsweep.sources import CodexSource  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "codex" / "rollout-sample.jsonl"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    return home


def _mk_codex_root(tmp_path: Path) -> Path:
    """Replicate the real ~/.codex layout: dated rollout dirs, history.jsonl,
    and an auth.json that must never be touched."""
    root = tmp_path / "codex"
    day = root / "sessions" / "2026" / "04" / "24"
    day.mkdir(parents=True)
    shutil.copy(FIXTURE, day / "rollout-2026-04-24T17-28-47-019dbf5b.jsonl")
    (root / "history.jsonl").write_text(
        json.dumps({"session_id": "x", "ts": 1, "text": "hello"}) + "\n",
        encoding="utf-8",
    )
    (root / "auth.json").write_text(
        '{"OPENAI_API_KEY": "not-scanned"}', encoding="utf-8"
    )
    return root


def test_default_root_is_dot_codex(_isolated_home):
    assert CodexSource().root == _isolated_home / ".codex"


def test_codex_home_env_selects_that_root(tmp_path, monkeypatch):
    relocated = tmp_path / "relocated-codex"
    monkeypatch.setenv("CODEX_HOME", str(relocated))
    assert CodexSource().root == relocated


def test_empty_codex_home_falls_back_to_dot_codex(_isolated_home, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", "")
    assert CodexSource().root == _isolated_home / ".codex"


def test_explicit_root_beats_codex_home_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "relocated-codex"))
    explicit = tmp_path / "explicit"
    assert CodexSource(root=explicit).root == explicit


def test_files_finds_jsonl_but_never_auth_json(tmp_path):
    root = _mk_codex_root(tmp_path)
    files = CodexSource(root=root).files()
    names = [f.name for f in files]
    assert "history.jsonl" in names
    assert any(n.startswith("rollout-") for n in names)
    assert "auth.json" not in names  # OAuth creds: structurally excluded


def test_iter_strings_walks_codex_payloads(tmp_path):
    root = _mk_codex_root(tmp_path)
    source = CodexSource(root=root)
    rollout = next(f for f in source.files() if f.name.startswith("rollout-"))
    values = [v for _, _, v in source.iter_strings(rollout)]
    assert any(AWS_KEY in v for v in values)


def test_cli_scan_and_fix_codex_source(tmp_path, monkeypatch, capsys):
    root = _mk_codex_root(tmp_path)
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))

    assert main(["--source", "codex", "--root", str(root)]) == 1

    code = main(["--source", "codex", "--root", str(root), "--fix", "--force"])
    assert code == 0
    rollout = next((root / "sessions").rglob("rollout-*.jsonl"))
    content = rollout.read_text(encoding="utf-8")
    assert AWS_KEY not in content
    assert "[REDACTED:aws-access-key]" in content
    # Line-by-line structure preserved (codex shape intact).
    for line in content.splitlines():
        assert json.loads(line)["type"] in {
            "session_meta",
            "event_msg",
            "response_item",
        }
    assert rollout.with_name(rollout.name + ".bak").exists()
    assert (root / "auth.json").read_text(
        encoding="utf-8"
    ) == '{"OPENAI_API_KEY": "not-scanned"}'


def test_cli_fix_refuses_codex_home_without_allow_production(
    tmp_path, monkeypatch, capsys
):
    root = _mk_codex_root(tmp_path)
    monkeypatch.setenv("CODEX_HOME", str(root))
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))

    code = main(["fix", "--source", "codex"])
    captured = capsys.readouterr()

    assert code == 2
    assert "default production root" in captured.err
    assert "--allow-production" in captured.err
    rollout = next((root / "sessions").rglob("rollout-*.jsonl"))
    assert AWS_KEY in rollout.read_text(encoding="utf-8")
    assert not rollout.with_name(rollout.name + ".bak").exists()


def test_active_session_gate_names_codex(tmp_path, monkeypatch, capsys):
    root = _mk_codex_root(tmp_path)
    monkeypatch.setattr(
        pipeline, "is_agent_running", lambda markers: (True, "codex.exe")
    )

    code = main(["--source", "codex", "--root", str(root), "--fix"])
    captured = capsys.readouterr()

    assert code == 2
    assert "Codex appears to be running" in captured.err


def test_preflight_detects_codex_tasklist(monkeypatch):
    monkeypatch.setattr(
        preflight,
        "_list_process_cmdlines",
        lambda: ['"codex.exe","51234","Console","1","180,000 K"'],
    )
    running, marker = preflight.is_agent_running(preflight.CODEX_MARKERS)
    assert running
    assert marker == "codex.exe"
