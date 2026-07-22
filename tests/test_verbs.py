"""Tests for verb dispatch, undo, and --version in cli.py / pipeline.py.

Covers:
  (a) --version / -V  →  print "agentsweep <ver>", exit 0
  (b) "scan --root R" == legacy "--root R" (same findings, same exit 1)
  (c) legacy "--root R --fix --force" still redacts (back-compat alias), exit 0
  (d) "fix" non-interactive with --force redacts, exit 0
  (e) "undo --root R" with .bak files present restores NON-interactively, exit 0
      undo with no backups: exit 0 with stderr note
      undo where restore fails: exit 2
  (f) undo INTERACTIVE path: y/n via monkeypatched isatty + is_terminal
  (g) unknown verb-ish first arg (starts with --) routes to scan/fix correctly
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import __version__  # noqa: E402
from agentsweep.cli import main  # noqa: E402

# ---------------------------------------------------------------------------
# Fake secrets — same values used throughout the test suite
# ---------------------------------------------------------------------------
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

_LINE = (
    '{"type":"user","message":{"role":"user","content":'
    f'[{{"type":"text","text":"key={AWS_KEY}"}}]}}}}\n'
)


# ---------------------------------------------------------------------------
# Autouse fixture: isolate HOME / USERPROFILE so ClaudeCodeSource().default_root()
# never accidentally points at the real ~/.claude/projects directory.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    yield fake_home


# ---------------------------------------------------------------------------
# Helper: build a scan root with one seeded JSONL file containing a secret.
# ---------------------------------------------------------------------------
def _seed_root(base: Path, content: str = _LINE, *, age_seconds: int = 3700) -> Path:
    root = base / "scan_root"
    root.mkdir(parents=True, exist_ok=True)
    f = root / "session.jsonl"
    f.write_text(content, encoding="utf-8")
    past = time.time() - age_seconds
    os.utime(f, (past, past))
    return root


# ---------------------------------------------------------------------------
# Helper: monkeypatch is_agent_running → not running
# ---------------------------------------------------------------------------
def _no_claude(monkeypatch):
    import agentsweep.pipeline as _pipeline

    monkeypatch.setattr(_pipeline, "is_agent_running", lambda markers: (False, ""))


# ===========================================================================
# (a) --version / -V
# ===========================================================================


def test_version_flag_prints_and_exits(capsys):
    code = main(["--version"])
    captured = capsys.readouterr()
    assert code == 0
    assert f"agentsweep {__version__}" in captured.out


def test_V_short_flag_prints_and_exits(capsys):
    code = main(["-V"])
    captured = capsys.readouterr()
    assert code == 0
    assert f"agentsweep {__version__}" in captured.out


def test_version_does_not_scan(tmp_path, capsys):
    """No scan output should appear — version flag exits before any scan."""
    root = _seed_root(tmp_path)
    code = main(["--version", "--root", str(root)])
    captured = capsys.readouterr()
    assert code == 0
    # The only output line should be the version string.
    non_empty = [l for l in captured.out.splitlines() if l.strip()]
    assert len(non_empty) == 1
    assert "agentsweep" in non_empty[0]


# ===========================================================================
# (b) "scan --root R" == legacy "--root R"  (findings / exit 1)
# ===========================================================================


def test_scan_verb_and_legacy_are_equivalent(tmp_path, monkeypatch, capsys):
    root = _seed_root(tmp_path)

    code_legacy = main(["--root", str(root), "--json"])
    out_legacy = capsys.readouterr().out

    code_verb = main(["scan", "--root", str(root), "--json"])
    out_verb = capsys.readouterr().out

    assert code_legacy == 1
    assert code_verb == 1
    # Both JSON outputs should contain the same secret rule hit.
    import json

    findings_legacy = json.loads(out_legacy)
    findings_verb = json.loads(out_verb)
    assert len(findings_legacy) == len(findings_verb)
    assert findings_legacy[0]["rule"] == findings_verb[0]["rule"]


def test_scan_verb_exits_1_with_findings(tmp_path, capsys):
    root = _seed_root(tmp_path)
    code = main(["scan", "--root", str(root), "--json"])
    assert code == 1
    import json

    findings = json.loads(capsys.readouterr().out)
    assert any(f["rule"] for f in findings)


def test_scan_verb_exits_0_on_clean_root(tmp_path, capsys):
    root = tmp_path / "clean_root"
    root.mkdir()
    clean = root / "session.jsonl"
    clean.write_text('{"type":"user","message":"nothing here"}\n', encoding="utf-8")
    past = time.time() - 9999
    os.utime(clean, (past, past))
    code = main(["scan", "--root", str(root), "--json"])
    assert code == 0


# ===========================================================================
# (c) Legacy "--root R --fix --force" still redacts (back-compat alias)
# ===========================================================================


def test_legacy_fix_force_redacts(tmp_path, monkeypatch, capsys):
    _no_claude(monkeypatch)
    root = _seed_root(tmp_path)
    session = root / "session.jsonl"

    code = main(["--root", str(root), "--fix", "--force", "--allow-production"])
    assert code == 0
    assert AWS_KEY not in session.read_text(encoding="utf-8")
    assert "[REDACTED:" in session.read_text(encoding="utf-8")


# ===========================================================================
# (d) "fix" non-interactive with --force redacts
# ===========================================================================


def test_fix_verb_noninteractive_redacts(tmp_path, monkeypatch, capsys):
    """Non-interactive fix (capsys = non-tty): --force bypasses mtime/process gates."""
    _no_claude(monkeypatch)
    root = _seed_root(tmp_path)
    session = root / "session.jsonl"

    code = main(["fix", "--root", str(root), "--force", "--allow-production"])
    assert code == 0
    content = session.read_text(encoding="utf-8")
    assert AWS_KEY not in content
    assert "[REDACTED:" in content


def test_fix_verb_creates_bak(tmp_path, monkeypatch, capsys):
    _no_claude(monkeypatch)
    root = _seed_root(tmp_path)

    main(["fix", "--root", str(root), "--force", "--allow-production"])
    assert (root / "session.jsonl.bak").exists()


# ===========================================================================
# (e) undo --root R
# ===========================================================================


def test_undo_restores_bak_noninteractively(tmp_path, monkeypatch, capsys):
    """Non-interactive undo (capsys = non-tty) should restore without prompting."""
    _no_claude(monkeypatch)
    root = _seed_root(tmp_path)
    session = root / "session.jsonl"
    original_content = session.read_text(encoding="utf-8")

    # Create a .bak file manually (simulating a previous --fix).
    bak = root / "session.jsonl.bak"
    bak.write_text(original_content, encoding="utf-8")
    # Simulate redacted main file.
    session.write_text(
        original_content.replace(AWS_KEY, "[REDACTED:aws-access-key-id]"),
        encoding="utf-8",
    )

    # Ensure non-interactive: sys.stdin.isatty() returns False under pytest capsys.
    code = main(["undo", "--root", str(root)])
    assert code == 0
    # Original content is restored.
    assert session.read_text(encoding="utf-8") == original_content
    # .bak file is consumed.
    assert not bak.exists()


def test_undo_no_backups_exits_0_with_stderr(tmp_path, capsys):
    """undo with no .bak files should exit 0 and emit a note to stderr."""
    root = _seed_root(tmp_path)

    code = main(["undo", "--root", str(root)])
    captured = capsys.readouterr()
    assert code == 0
    assert ".bak" in captured.err or "No" in captured.err


def test_undo_nonexistent_root_exits_0(tmp_path, capsys):
    """undo on a missing root is treated as nothing-to-do, not an error."""
    missing = tmp_path / "does_not_exist"
    code = main(["undo", "--root", str(missing)])
    assert code == 0
    assert "No history root" in capsys.readouterr().err


def test_undo_restore_failure_exits_2(tmp_path, monkeypatch, capsys):
    """If os.replace fails for any backup, undo should exit 2."""
    root = _seed_root(tmp_path)
    session = root / "session.jsonl"
    original_content = session.read_text(encoding="utf-8")

    bak = root / "session.jsonl.bak"
    bak.write_text(original_content, encoding="utf-8")

    # Patch os.replace to always raise OSError.
    import agentsweep.pipeline as _pipeline

    real_os_replace = _pipeline.os.replace if hasattr(_pipeline, "os") else None

    # Patch within the undo function's imported os module.
    import os as _os_mod

    original_replace = _os_mod.replace

    def _fail_replace(src, dst):
        raise OSError("simulated permission denied")

    monkeypatch.setattr(_os_mod, "replace", _fail_replace)

    code = main(["undo", "--root", str(root)])
    assert code == 2


# ===========================================================================
# (f) undo INTERACTIVE path: confirm (y) and cancel (n)
# ===========================================================================


def _make_terminal_console():
    """Return a simple namespace that looks like a terminal console to pipeline.undo."""

    class _FakeConsole:
        is_terminal = True

        # Rich Console methods used by ui — no-op stubs.
        def print(self, *a, **kw):
            pass

        def rule(self, *a, **kw):
            pass

    return _FakeConsole()


def test_undo_interactive_y_restores(tmp_path, monkeypatch, capsys):
    """When interactive and user types 'y', backups are restored."""
    root = _seed_root(tmp_path)
    session = root / "session.jsonl"
    original_content = session.read_text(encoding="utf-8")

    bak = root / "session.jsonl.bak"
    bak.write_text(original_content, encoding="utf-8")
    session.write_text(
        original_content.replace(AWS_KEY, "[REDACTED:aws-access-key-id]"),
        encoding="utf-8",
    )

    # Make the undo function think it's interactive by:
    # 1. making sys.stdin.isatty() return True
    # 2. replacing ui.console with a fake that has is_terminal=True
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    import agentsweep.ui as _ui
    import agentsweep.pipeline as _pipeline

    fake_console = _make_terminal_console()
    monkeypatch.setattr(_ui, "console", fake_console)
    monkeypatch.setattr(_pipeline, "ui", _ui)

    # Feed "y" to the input() call inside undo.
    inputs = iter(["y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))

    code = main(["undo", "--root", str(root)])
    assert code == 0
    assert session.read_text(encoding="utf-8") == original_content
    assert not bak.exists()


def test_undo_interactive_n_cancels(tmp_path, monkeypatch, capsys):
    """When interactive and user types 'n', backups are NOT restored."""
    root = _seed_root(tmp_path)
    session = root / "session.jsonl"
    original_content = session.read_text(encoding="utf-8")

    bak = root / "session.jsonl.bak"
    bak.write_text(original_content, encoding="utf-8")
    redacted_content = original_content.replace(AWS_KEY, "[REDACTED:aws-access-key-id]")
    session.write_text(redacted_content, encoding="utf-8")

    # Make the undo function think it's interactive.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    import agentsweep.ui as _ui
    import agentsweep.pipeline as _pipeline

    fake_console = _make_terminal_console()
    monkeypatch.setattr(_ui, "console", fake_console)
    monkeypatch.setattr(_pipeline, "ui", _ui)

    # Feed "n" to the input() call.
    inputs = iter(["n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))

    code = main(["undo", "--root", str(root)])
    assert code == 0
    # Session file is unchanged (still redacted).
    assert session.read_text(encoding="utf-8") == redacted_content
    # .bak is still present.
    assert bak.exists()


def test_undo_interactive_eof_cancels_gracefully(tmp_path, monkeypatch, capsys):
    """EOFError from input() in interactive undo should exit 0 cleanly."""
    root = _seed_root(tmp_path)
    session = root / "session.jsonl"
    original_content = session.read_text(encoding="utf-8")
    bak = root / "session.jsonl.bak"
    bak.write_text(original_content, encoding="utf-8")

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    import agentsweep.ui as _ui
    import agentsweep.pipeline as _pipeline

    fake_console = _make_terminal_console()
    monkeypatch.setattr(_ui, "console", fake_console)
    monkeypatch.setattr(_pipeline, "ui", _ui)

    def _raise_eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)

    code = main(["undo", "--root", str(root)])
    assert code == 0
    # .bak kept (cancelled).
    assert bak.exists()


# ===========================================================================
# (g) Unknown verb-ish first arg (starts with --) routes to scan/fix correctly
# ===========================================================================


def test_double_dash_arg_routes_to_scan(tmp_path, capsys):
    """An arg starting with -- that is not a verb is routed to scan."""
    root = _seed_root(tmp_path)
    # --root is a flag, not a verb → should route to scan.
    code = main(["--root", str(root), "--json"])
    assert code == 1  # findings found → scan exit 1
    import json

    out = capsys.readouterr().out
    findings = json.loads(out)
    assert len(findings) > 0


def test_double_dash_fix_routes_to_fix_verb(tmp_path, monkeypatch, capsys):
    """--fix is the legacy alias and should route to the fix verb."""
    _no_claude(monkeypatch)
    root = _seed_root(tmp_path)
    session = root / "session.jsonl"

    code = main(["--fix", "--root", str(root), "--force", "--allow-production"])
    assert code == 0
    assert AWS_KEY not in session.read_text(encoding="utf-8")


def test_source_flag_still_works_with_verb(tmp_path, capsys):
    """--source flag works alongside verb dispatch."""
    # Use claude-code source explicitly.
    root = _seed_root(tmp_path)
    code = main(["scan", "--root", str(root), "--source", "claude-code", "--json"])
    assert code == 1


# ===========================================================================
# Additional edge cases
# ===========================================================================


def test_undo_multiple_bak_files(tmp_path, monkeypatch, capsys):
    """undo with multiple .bak files restores all of them."""
    _no_claude(monkeypatch)
    root = _seed_root(tmp_path)
    # Create a sub-directory with another session.
    subdir = root / "sub"
    subdir.mkdir()
    f2 = subdir / "other.jsonl"
    f2.write_text(_LINE, encoding="utf-8")
    past = time.time() - 9999
    os.utime(f2, (past, past))

    # Create two .bak files.
    (root / "session.jsonl.bak").write_text("original1\n", encoding="utf-8")
    (subdir / "other.jsonl.bak").write_text("original2\n", encoding="utf-8")

    code = main(["undo", "--root", str(root)])
    assert code == 0
    # Both main files are overwritten by bak content.
    assert (root / "session.jsonl").read_text(encoding="utf-8") == "original1\n"
    assert (subdir / "other.jsonl").read_text(encoding="utf-8") == "original2\n"
    # Both .bak files consumed.
    assert not (root / "session.jsonl.bak").exists()
    assert not (subdir / "other.jsonl.bak").exists()


def test_fix_verb_noninteractive_no_allow_production_blocks(
    tmp_path, monkeypatch, capsys
):
    """Non-interactive fix without --allow-production on default root is blocked (exit 2)."""
    _no_claude(monkeypatch)
    fake_home = tmp_path / "home"
    # The fixture already set this up; ClaudeCodeSource().default_root() now points to
    # fake_home/.claude/projects which equals our scan root.
    root = fake_home / ".claude" / "projects"
    root.mkdir(parents=True)
    session = root / "session.jsonl"
    session.write_text(_LINE, encoding="utf-8")
    past = time.time() - 9999
    os.utime(session, (past, past))

    code = main(["fix", "--force"])  # no --allow-production
    captured = capsys.readouterr()
    assert code == 2
    assert (
        "default production root" in captured.err or "allow-production" in captured.err
    )
    # Nothing redacted.
    assert AWS_KEY in session.read_text(encoding="utf-8")


def test_scan_json_flag_produces_parseable_output(tmp_path, capsys):
    """scan --json should produce parseable JSON with fingerprint field."""
    import json

    root = _seed_root(tmp_path)
    code = main(["scan", "--root", str(root), "--json"])
    assert code == 1
    out = capsys.readouterr().out
    findings = json.loads(out)
    assert len(findings) > 0
    assert "fingerprint" in findings[0]
    assert "rule" in findings[0]
    assert "file" in findings[0]
    assert "line" in findings[0]


def test_completion_bash(capsys):
    code = main(["completion", "bash"])
    assert code == 0
    captured = capsys.readouterr()
    assert "complete" in captured.out
    assert "agentsweep" in captured.out


def test_completion_zsh(capsys):
    code = main(["completion", "zsh"])
    assert code == 0
    captured = capsys.readouterr()
    assert "complete" in captured.out or "agentsweep" in captured.out


def test_completion_fish(capsys):
    code = main(["completion", "fish"])
    assert code == 0
    captured = capsys.readouterr()
    assert "complete" in captured.out
    assert "agentsweep" in captured.out


def test_completion_powershell(capsys):
    code = main(["completion", "powershell"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Register-ArgumentCompleter" in captured.out
    assert "agentsweep" in captured.out


def test_completion_rejects_unknown_shell():
    with pytest.raises(SystemExit):
        main(["completion", "tcsh"])


def test_completion_missing_argcomplete_exits_2(monkeypatch, capsys):
    fake_argcomplete = types.ModuleType("argcomplete")
    setattr(fake_argcomplete, "autocomplete", lambda parser: None)
    monkeypatch.setitem(sys.modules, "argcomplete", fake_argcomplete)

    code = main(["completion", "bash"])

    assert code == 2
    assert "argcomplete is not installed" in capsys.readouterr().err


def test_completion_setup_does_not_swallow_parser_errors(monkeypatch):
    import agentsweep.cli as cli

    fake_argcomplete = types.ModuleType("argcomplete")
    setattr(fake_argcomplete, "autocomplete", lambda parser: None)
    monkeypatch.setitem(sys.modules, "argcomplete", fake_argcomplete)

    def _fail_parser():
        raise RuntimeError("broken completion parser")

    monkeypatch.setattr(cli, "_get_completion_parser", _fail_parser)

    with pytest.raises(RuntimeError, match="broken completion parser"):
        main(["scan"])


def test_fix_completion_matches_the_cli_contract():
    from agentsweep.cli import _get_completion_parser

    parser = _get_completion_parser()
    subparsers_action = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    fix_parser = subparsers_action.choices["fix"]
    fix_options = {
        option for action in fix_parser._actions for option in action.option_strings
    }

    # #53's contract: completions advertise exactly what fix accepts. fix --all
    # is supported now, so advertising it is what keeps that contract true.
    assert "--all" in fix_options
    assert "--detected" in fix_options


def test_source_completer_matches():
    from agentsweep.cli import source_completer

    res = source_completer("clau")
    assert "claude-code" in res
    res_all = source_completer("")
    assert len(res_all) > 10
