"""fix --all: sequential per-source redaction with independent gates.

Each source runs the single-source fix path, so a gate block on one must not
cost the others their redaction — that is the whole point of --all over the
per-source loop it replaces.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline  # noqa: E402
from agentsweep.cli import main  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

_CLAUDE_LINE = (
    '{{"type":"user","message":{{"role":"user","content":'
    '[{{"type":"text","text":"key={secret}"}}]}}}}\n'
)


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    """Isolate HOME and the Windows/XDG dirs so multi-source discovery is
    hermetic — every registered source is visited here, and the ones rooted at
    APPDATA/LOCALAPPDATA would otherwise read the real machine's history."""
    home = tmp_path / "home"
    home.mkdir()
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    appdata = tmp_path / "appdata"
    appdata.mkdir()
    local = tmp_path / "localappdata"
    local.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg / "config"))
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("AGENTSWEEP_NO_UPDATE", "1")
    return home


@pytest.fixture(autouse=True)
def _no_agent_running(monkeypatch):
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))


@pytest.fixture(autouse=True)
def _non_interactive(monkeypatch):
    # capsys already makes stdout a non-tty; pin stdin too so the per-source
    # REDACT prompt never fires and a hang can't masquerade as a pass.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)


def _age(p: Path, seconds: int = 3700) -> None:
    past = time.time() - seconds
    os.utime(p, (past, past))


def _seed_claude(home: Path, secret: str = AWS_KEY, *, age: int = 3700) -> Path:
    d = home / ".claude" / "projects" / "proj"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "session.jsonl"
    f.write_text(_CLAUDE_LINE.format(secret=secret), encoding="utf-8")
    _age(f, age)
    return f


def _seed_codex(home: Path, secret: str = GH_TOKEN, *, age: int = 3700) -> Path:
    d = home / ".codex" / "sessions" / "2026" / "04" / "24"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "rollout-2026-04-24T17-28-47-019dbf5b.jsonl"
    f.write_text(
        json.dumps({"type": "event_msg", "text": f"token={secret}"}) + "\n",
        encoding="utf-8",
    )
    _age(f, age)
    return f


def test_fix_all_redacts_every_source(_isolate_home, capsys):
    claude = _seed_claude(_isolate_home)
    codex = _seed_codex(_isolate_home)

    code = main(["fix", "--all", "--force", "--allow-production"])

    assert code == 0
    assert AWS_KEY not in claude.read_text(encoding="utf-8")
    assert GH_TOKEN not in codex.read_text(encoding="utf-8")
    assert "[REDACTED:aws-access-key]" in claude.read_text(encoding="utf-8")
    assert "[REDACTED:github-pat]" in codex.read_text(encoding="utf-8")


def test_each_source_gets_its_own_backup(_isolate_home, capsys):
    claude = _seed_claude(_isolate_home)
    codex = _seed_codex(_isolate_home)

    assert main(["fix", "--all", "--force", "--allow-production"]) == 0

    assert claude.with_name(claude.name + ".bak").exists()
    assert codex.with_name(codex.name + ".bak").exists()


def test_each_source_gets_its_own_audit_entry(_isolate_home, capsys):
    _seed_claude(_isolate_home)
    _seed_codex(_isolate_home)

    assert main(["fix", "--all", "--force", "--allow-production"]) == 0

    audit = _isolate_home / ".agentsweep" / "audit.jsonl"
    entries = [json.loads(x) for x in
               audit.read_text(encoding="utf-8").splitlines() if x.strip()]
    written = {Path(e["path"]).name for e in entries}
    assert "session.jsonl" in written
    assert any(n.startswith("rollout-") for n in written)


def test_gate_block_on_one_source_leaves_others_redacted(_isolate_home, capsys):
    claude = _seed_claude(_isolate_home)
    # Fresh mtime: trips the active-session gate for codex only. --force would
    # bypass it, so this run deliberately omits it.
    codex = _seed_codex(_isolate_home, age=1)

    code = main(["fix", "--all", "--allow-production"])

    assert code == 2
    assert AWS_KEY not in claude.read_text(encoding="utf-8")   # still redacted
    assert GH_TOKEN in codex.read_text(encoding="utf-8")       # left untouched
    assert not codex.with_name(codex.name + ".bak").exists()


def test_blocked_source_is_named_in_output(_isolate_home, capsys):
    _seed_claude(_isolate_home)
    _seed_codex(_isolate_home, age=1)

    main(["fix", "--all", "--allow-production"])
    out = capsys.readouterr().out

    assert "codex" in out
    assert "unresolved" in out


def test_clean_machine_exits_zero(_isolate_home, capsys):
    assert main(["fix", "--all", "--allow-production"]) == 0


def test_undo_reverts_every_source(_isolate_home, capsys):
    claude = _seed_claude(_isolate_home)
    codex = _seed_codex(_isolate_home)
    claude_before = claude.read_bytes()
    codex_before = codex.read_bytes()

    assert main(["fix", "--all", "--force", "--allow-production"]) == 0
    assert main(["undo", "--source", "claude-code"]) == 0
    assert main(["undo", "--source", "codex"]) == 0

    assert claude.read_bytes() == claude_before
    assert codex.read_bytes() == codex_before


def test_no_secret_plaintext_in_output(_isolate_home, capsys):
    _seed_claude(_isolate_home)
    _seed_codex(_isolate_home)

    main(["fix", "--all", "--force", "--allow-production"])
    captured = capsys.readouterr()

    assert AWS_KEY not in captured.out
    assert GH_TOKEN not in captured.out


def test_fix_all_detected_only_visits_existing_roots(_isolate_home, capsys):
    claude = _seed_claude(_isolate_home)

    code = main(["fix", "--all", "--detected", "--force", "--allow-production"])

    assert code == 0
    assert AWS_KEY not in claude.read_text(encoding="utf-8")


def test_json_stays_scan_only(_isolate_home, capsys):
    """--json short-circuits before redaction, matching fix --source --json."""
    claude = _seed_claude(_isolate_home)

    code = main(["fix", "--all", "--json", "--force", "--allow-production"])
    out = capsys.readouterr().out

    assert code == 1
    assert json.loads(out)  # parseable, and still a findings list
    assert AWS_KEY in claude.read_text(encoding="utf-8")
