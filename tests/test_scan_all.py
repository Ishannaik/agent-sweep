"""Tests for `agentsweep scan --all` multi-source aggregated scanning.

Covers:
  (a) empty HOME → exit 0, JSON []
  (b) one seeded source → exit 1, findings tagged with that source
  (c) two seeded sources → findings from both, distinguished by "source"
  (d) --all --detected only visits roots that exist
  (e) --all + --source / --root / fix --all rejected
  (f) --detected without --all rejected
  (g) human mode stages + no raw secrets
  (h) --json -o writes aggregated file, clean stdout
  (i) ignore file suppresses only the source it sits under
  (j) single-source scan still works and includes "source" field
  (k) legacy form: agentsweep --all --json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import main  # noqa: E402
from agentsweep.sources import SOURCES  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

CLAUDE_LINE = (
    '{"type":"user","message":{"content":[{"type":"text",'
    f'"text":"aws key={AWS_KEY}"}}]}}}}\n'
)
CODEX_LINE = (
    '{"type":"message","role":"user","content":'
    f'"token {GH_TOKEN}"}}\n'
)


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    """Isolate HOME and Windows/XDG dirs so multi-source discovery is hermetic."""
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


def _seed_claude(home: Path, content: str = CLAUDE_LINE) -> Path:
    root = home / ".claude" / "projects"
    root.mkdir(parents=True, exist_ok=True)
    path = root / "session.jsonl"
    path.write_text(content, encoding="utf-8")
    return root


def _seed_codex(home: Path, content: str = CODEX_LINE) -> Path:
    # CodexSource walks ~/.codex (sessions + root jsonl files).
    root = home / ".codex"
    sess = root / "sessions" / "2026" / "01" / "01"
    sess.mkdir(parents=True, exist_ok=True)
    (sess / "rollout-test.jsonl").write_text(content, encoding="utf-8")
    return root


def _scan_all_json(extra=None, capsys=None):
    argv = ["scan", "--all", "--json"] + (extra or [])
    code = main(argv)
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else []
    return code, payload, captured.err


# ---------------------------------------------------------------------------
# (a) empty
# ---------------------------------------------------------------------------

def test_scan_all_empty_home_is_clean(capsys):
    code, payload, _err = _scan_all_json(capsys=capsys)
    assert code == 0
    assert payload == []


def test_scan_all_detected_empty_is_clean(capsys):
    code = main(["scan", "--all", "--detected", "--json"])
    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(out) == []


# ---------------------------------------------------------------------------
# (b) single seeded source
# ---------------------------------------------------------------------------

def test_scan_all_one_source_tags_findings(_isolate_env, capsys):
    _seed_claude(_isolate_env)
    code, payload, _err = _scan_all_json(capsys=capsys)
    assert code == 1
    assert payload
    assert all(item["source"] == "claude-code" for item in payload)
    assert any(item["rule"] for item in payload)
    raw = json.dumps(payload)
    assert AWS_KEY not in raw


# ---------------------------------------------------------------------------
# (c) two sources
# ---------------------------------------------------------------------------

def test_scan_all_two_sources_aggregate(_isolate_env, capsys):
    _seed_claude(_isolate_env)
    _seed_codex(_isolate_env)
    code, payload, _err = _scan_all_json(capsys=capsys)
    assert code == 1
    sources = {item["source"] for item in payload}
    assert "claude-code" in sources
    assert "codex" in sources
    # Each finding has the additive schema fields.
    for item in payload:
        assert "source" in item
        assert "fingerprint" in item
        assert "rule" in item
        assert "masked" in item
        assert "file" in item
        assert "line" in item
        assert "keypath" in item
        assert "display" in item


# ---------------------------------------------------------------------------
# (d) --detected
# ---------------------------------------------------------------------------

def test_scan_all_detected_skips_absent_roots(_isolate_env, capsys):
    # Only claude-code root exists; codex is absent.
    _seed_claude(_isolate_env)
    code, payload, _err = _scan_all_json(extra=["--detected"], capsys=capsys)
    assert code == 1
    assert payload
    assert all(item["source"] == "claude-code" for item in payload)
    assert not any(item["source"] == "codex" for item in payload)


def test_scan_all_detected_includes_both_when_present(_isolate_env, capsys):
    _seed_claude(_isolate_env)
    _seed_codex(_isolate_env)
    code, payload, _err = _scan_all_json(extra=["--detected"], capsys=capsys)
    assert code == 1
    sources = {item["source"] for item in payload}
    assert sources >= {"claude-code", "codex"}


# ---------------------------------------------------------------------------
# (e) / (f) flag rejection
# ---------------------------------------------------------------------------

def test_scan_all_rejects_source_flag():
    with pytest.raises(SystemExit) as ei:
        main(["scan", "--all", "--source", "codex"])
    assert ei.value.code == 2


def test_scan_all_rejects_root_flag(tmp_path):
    with pytest.raises(SystemExit) as ei:
        main(["scan", "--all", "--root", str(tmp_path)])
    assert ei.value.code == 2


def test_fix_all_rejected():
    with pytest.raises(SystemExit) as ei:
        main(["fix", "--all"])
    assert ei.value.code == 2


def test_detected_without_all_rejected():
    with pytest.raises(SystemExit) as ei:
        main(["scan", "--detected"])
    assert ei.value.code == 2


# ---------------------------------------------------------------------------
# (g) human mode
# ---------------------------------------------------------------------------

def test_scan_all_human_mode_stages(_isolate_env, capsys):
    _seed_claude(_isolate_env)
    _seed_codex(_isolate_env)
    code = main(["scan", "--all"])
    out = capsys.readouterr().out
    assert code == 1
    assert "DISCOVER" in out
    assert "SCAN" in out
    assert "FINDINGS" in out
    assert "claude-code" in out
    assert "codex" in out
    assert AWS_KEY not in out
    assert GH_TOKEN not in out
    # Points at per-source fix, not fix --all
    assert "fix --source" in out


def test_scan_all_human_clean(_isolate_env, capsys):
    # Empty roots that exist but have no history files still clean.
    (_isolate_env / ".claude" / "projects").mkdir(parents=True)
    code = main(["scan", "--all", "--detected"])
    out = capsys.readouterr().out
    assert code == 0
    assert "no secrets" in out.lower() or "FINDINGS" in out


# ---------------------------------------------------------------------------
# (h) -o file
# ---------------------------------------------------------------------------

def test_scan_all_json_output_file(_isolate_env, tmp_path, capsys):
    _seed_claude(_isolate_env)
    out_file = tmp_path / "all-findings.json"
    code = main(["scan", "--all", "--json", "-o", str(out_file)])
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out.strip() == ""
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload
    assert all(item["source"] == "claude-code" for item in payload)
    assert AWS_KEY not in out_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# (i) ignore per source
# ---------------------------------------------------------------------------

def test_scan_all_respects_per_source_ignore(_isolate_env, capsys):
    claude_root = _seed_claude(_isolate_env)
    _seed_codex(_isolate_env)
    # Suppress everything under claude-code via fingerprint-style ignore of rule.
    # .agentsweepignore supports rule names — suppress aws-access-key only there.
    (claude_root / ".agentsweepignore").write_text(
        "rule:aws-access-key\n", encoding="utf-8"
    )
    code, payload, _err = _scan_all_json(capsys=capsys)
    # Codex finding should remain; claude aws may be suppressed.
    sources = {item["source"] for item in payload}
    assert "codex" in sources
    assert "claude-code" not in sources or not any(
        i["source"] == "claude-code" and "aws" in i["rule"] for i in payload
    )


# ---------------------------------------------------------------------------
# (j) single-source regression — source field present
# ---------------------------------------------------------------------------

def test_single_source_json_includes_source_field(tmp_path, capsys):
    root = tmp_path / "history"
    root.mkdir()
    (root / "session.jsonl").write_text(CLAUDE_LINE, encoding="utf-8")
    code = main(["scan", "--root", str(root), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload
    assert all(item.get("source") == "claude-code" for item in payload)


def test_single_source_default_still_works(_isolate_env, capsys):
    _seed_claude(_isolate_env)
    code = main(["scan", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert all(item["source"] == "claude-code" for item in payload)


# ---------------------------------------------------------------------------
# (k) legacy flag form
# ---------------------------------------------------------------------------

def test_legacy_all_json_form(_isolate_env, capsys):
    _seed_claude(_isolate_env)
    code = main(["--all", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload
    assert all(item["source"] == "claude-code" for item in payload)


def test_scan_all_sources_order_stable(_isolate_env, capsys):
    """Findings sources appear in SOURCES registration order, not random."""
    _seed_claude(_isolate_env)
    _seed_codex(_isolate_env)
    _code, payload, _err = _scan_all_json(capsys=capsys)
    seen = []
    for item in payload:
        if item["source"] not in seen:
            seen.append(item["source"])
    registered = [k for k in SOURCES if k in seen]
    assert seen == registered
