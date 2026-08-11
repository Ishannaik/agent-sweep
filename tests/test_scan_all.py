"""Tests for `agentsweep scan --all` multi-source aggregated scanning.

Covers:
  (a) empty HOME → exit 0, JSON []
  (b) one seeded source → exit 1, findings tagged with that source
  (c) two seeded sources → findings from both, distinguished by "source"
  (d) --all --detected only visits roots that exist
  (e) --all + --source / --root rejected; fix --all accepted
  (f) --detected without --all rejected
  (g) human mode stages + no raw secrets
  (h) --json -o writes aggregated file, clean stdout
  (i) ignore file suppresses only the source it sits under
  (j) single-source scan still works and includes "source" field
  (k) legacy form: agentsweep --all --json
  (l) multi-source overflow report is aggregated (not clobbered per source)
  (m) scan --all --json emits truncation warning on stderr
  (n) menu._scan_all_sources shells out via cli.main(["scan", "--all"])
  (o) -o with multi-source overflow does not write agentsweep-report.txt
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline  # noqa: E402
from agentsweep import menu as menu_mod  # noqa: E402
from agentsweep.cli import main  # noqa: E402
from agentsweep.sources import SOURCES  # noqa: E402
from rich.console import Console  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

CLAUDE_LINE = (
    '{"type":"user","message":{"content":[{"type":"text",'
    f'"text":"aws key={AWS_KEY}"}}]}}}}\n'
)
CODEX_LINE = f'{{"type":"message","role":"user","content":"token {GH_TOKEN}"}}\n'


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


def test_scan_all_exclude_rule_filters_aggregated_findings(_isolate_env, capsys):
    _seed_claude(
        _isolate_env,
        content=(
            '{"type":"user","message":{"content":[{"type":"text",'
            f'"text":"key={AWS_KEY} and token {GH_TOKEN}"' + "}]}}\n"
        ),
    )

    code, payload, _err = _scan_all_json(
        extra=["--exclude-rule", "aws-access-key"],
        capsys=capsys,
    )

    assert code == 1
    assert payload
    assert all(item["source"] == "claude-code" for item in payload)
    assert {item["rule"] for item in payload} == {"github-pat"}


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


def test_fix_all_is_accepted():
    # Parse-level only: fix --all is supported now, so calling main() here
    # would scan the real machine instead of tmp_path.
    from agentsweep.cli import _parse_run

    args = _parse_run("fix", ["--all"])
    assert args.all is True
    assert args.fix is True


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
    # Scan stops at FINDINGS and points at the redaction flag, never redacting.
    assert "--fix" in out


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


# ---------------------------------------------------------------------------
# (l) multi-source overflow report is not clobbered
# ---------------------------------------------------------------------------


def _seed_many_claude(home: Path, n: int) -> None:
    root = home / ".claude" / "projects"
    root.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (root / f"session_{i}.jsonl").write_text(CLAUDE_LINE, encoding="utf-8")


def _seed_many_codex(home: Path, n: int) -> None:
    root = home / ".codex" / "sessions" / "2026" / "01" / "01"
    root.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (root / f"rollout-{i}.jsonl").write_text(CODEX_LINE, encoding="utf-8")


def test_scan_all_overflow_report_includes_all_sources(
    _isolate_env,
    tmp_path,
    monkeypatch,
    capsys,
):
    """Two large sources must not clobber agentsweep-report.txt to last-only."""
    _seed_many_claude(_isolate_env, 45)
    _seed_many_codex(_isolate_env, 45)
    monkeypatch.chdir(tmp_path)

    with patch.object(
        Console, "is_terminal", new_callable=lambda: property(lambda self: True)
    ):
        code = main(["scan", "--all"])
        captured = capsys.readouterr()

    assert code == 1
    report = tmp_path / pipeline.DEFAULT_REPORT_NAME
    assert report.exists(), "aggregated overflow report must be written once"
    text = report.read_text(encoding="utf-8")
    assert "[claude-code]" in text
    assert "[codex]" in text
    assert "all sources" in text.lower()
    # Raw secrets never land in the report
    assert AWS_KEY not in text
    assert GH_TOKEN not in text
    combined = captured.out + captured.err
    assert report.name in combined or "full multi-source" in combined.lower()


def test_scan_all_overflow_with_dash_o_skips_default_report(
    _isolate_env,
    tmp_path,
    monkeypatch,
    capsys,
):
    """When -o is set, full JSON goes there — no agentsweep-report.txt clobber path."""
    _seed_many_claude(_isolate_env, 45)
    _seed_many_codex(_isolate_env, 45)
    monkeypatch.chdir(tmp_path)
    out_file = tmp_path / "multi.json"

    with patch.object(
        Console, "is_terminal", new_callable=lambda: property(lambda self: True)
    ):
        code = main(["scan", "--all", "-o", str(out_file)])

    assert code == 1
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    sources = {item["source"] for item in payload}
    assert "claude-code" in sources and "codex" in sources
    assert not (tmp_path / pipeline.DEFAULT_REPORT_NAME).exists()


# ---------------------------------------------------------------------------
# (m) JSON truncation warning
# ---------------------------------------------------------------------------


def test_scan_all_json_emits_truncation_warning(_isolate_env, monkeypatch, capsys):
    """scan --all --json must stderr-warn when the scan budget truncates files."""
    _seed_claude(_isolate_env)
    # Tiny budget forces every non-empty string walk to truncate.
    monkeypatch.setattr(pipeline, "_MAX_FILE_SCAN_CHARS", 1)

    code = main(["scan", "--all", "--json"])
    captured = capsys.readouterr()

    # May be 0 or 1 depending on whether any secret fit before the cap;
    # the contract under test is the warning, not the findings.
    assert code in (0, 1)
    assert "truncated" in captured.err.lower()
    assert "scan budget" in captured.err.lower()
    # stdout still parseable JSON
    json.loads(captured.out)


# ---------------------------------------------------------------------------
# (n) menu uses cli.main
# ---------------------------------------------------------------------------


def test_menu_scan_all_shells_out_to_cli_main(monkeypatch):
    """_scan_all_sources must call cli.main(['scan', '--all']), not hand-roll args."""
    seen: list[list[str]] = []

    def fake_main(argv=None):
        seen.append(list(argv or []))
        return 0

    monkeypatch.setattr("agentsweep.cli.main", fake_main)
    menu_mod._scan_all_sources()
    assert seen == [["scan", "--all"]]
