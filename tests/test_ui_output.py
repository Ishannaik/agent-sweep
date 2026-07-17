"""Contract tests for the pipeline UI: --json purity, exit codes, masking,
gate rendering, redact rows, and encoding degradation."""
from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import cli, pipeline, ui  # noqa: E402
from agentsweep.cli import main  # noqa: E402


AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
FIXTURE_LINE = (
    '{"type":"user","message":{"content":[{"type":"text",'
    f'"text":"key={AWS_KEY} and token {GH_TOKEN}"}}]}}}}\n'
)
ANSI_ESCAPE = re.compile(r"\x1b\[")


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Keep every test away from the real home (audit log at ~/.agentsweep/ lives there)."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def _no_claude(monkeypatch):
    """Make the running-process gate deterministic (we test it explicitly)."""
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))


def _mkroot(tmp_path: Path, content: str = FIXTURE_LINE) -> Path:
    root = tmp_path / "history"
    root.mkdir()
    (root / "session.jsonl").write_text(content, encoding="utf-8")
    return root


# ---------------------------------------------------------------- json mode

def test_json_mode_is_machine_clean(tmp_path, capsys):
    root = _mkroot(tmp_path)
    code = main(["--root", str(root), "--json"])
    out = capsys.readouterr().out

    assert code == 1
    payload = json.loads(out)  # whole stdout must be valid JSON
    assert {f["rule"] for f in payload} == {"aws-access-key", "github-pat"}
    assert not ANSI_ESCAPE.search(out)
    assert "AGENTSWEEP" not in out


def test_json_mode_clean_history_exits_zero(tmp_path, capsys):
    root = _mkroot(tmp_path, '{"message":"hello world"}\n')
    code = main(["--root", str(root), "--json"])
    out = capsys.readouterr().out

    assert code == 0
    assert json.loads(out) == []


def test_json_mode_empty_root_still_emits_json(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    code = main(["--root", str(empty), "--json"])
    captured = capsys.readouterr()

    assert code == 0
    assert json.loads(captured.out) == []
    assert "No history files found" in captured.err


def test_json_with_fix_is_scan_only(tmp_path, capsys):
    """Pin inherited behavior: --json ignores --fix and never writes."""
    root = _mkroot(tmp_path)
    code = main(["--root", str(root), "--fix", "--force", "--json"])
    out = capsys.readouterr().out

    assert code == 1
    assert json.loads(out)
    assert AWS_KEY in (root / "session.jsonl").read_text(encoding="utf-8")
    assert not (root / "session.jsonl.bak").exists()


# ---------------------------------------------------------------- scan mode

def test_scan_exit_codes(tmp_path, capsys):
    dirty = _mkroot(tmp_path)
    assert main(["--root", str(dirty)]) == 1

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "s.jsonl").write_text('{"message":"hi"}\n', encoding="utf-8")
    assert main(["--root", str(clean)]) == 0


def test_human_empty_root_notice_on_stderr(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    code = main(["--root", str(empty)])
    captured = capsys.readouterr()

    assert code == 0
    assert "No history files found" in captured.err  # old CLI's stream contract


def test_human_output_pipeline_and_masking(tmp_path, capsys):
    root = _mkroot(tmp_path)
    code = main(["--root", str(root)])
    out = capsys.readouterr().out

    assert code == 1
    assert "AGENTSWEEP" in out
    for stage_name in ("DISCOVER", "SCAN", "FINDINGS", "REDACT", "ROTATE"):
        assert stage_name in out
    assert "ACTION REQUIRED" in out
    # Raw secret values must never reach the screen — masked forms only.
    assert AWS_KEY not in out
    assert GH_TOKEN not in out


def test_bracketed_path_segments_survive_rendering(tmp_path, capsys):
    """A Next.js-style `[id]` directory must not be eaten as rich markup."""
    root = tmp_path / "history"
    (root / "[id]").mkdir(parents=True)
    (root / "[id]" / "s.jsonl").write_text(FIXTURE_LINE, encoding="utf-8")

    code = main(["--root", str(root)])
    out = capsys.readouterr().out

    assert code == 1
    assert "[id]" in out


# ----------------------------------------------------------------- gates

def test_production_gate_blocks_and_still_shows_rotation(
        tmp_path, _isolated_home, capsys):
    fake_root = _isolated_home / ".claude" / "projects"
    fake_root.mkdir(parents=True)
    (fake_root / "session.jsonl").write_text(FIXTURE_LINE, encoding="utf-8")

    code = main(["--fix"])
    captured = capsys.readouterr()

    assert code == 2
    assert "default production root" in captured.err
    assert "--allow-production" in captured.err
    # The blocked user still gets rotation guidance — keys are live.
    assert "ACTION REQUIRED" in captured.out
    assert "[5/5]" in captured.out


def test_active_session_gate_blocks(tmp_path, monkeypatch, capsys):
    root = _mkroot(tmp_path)
    monkeypatch.setattr(pipeline, "is_agent_running",
                        lambda markers: (True, "claude.exe"))

    code = main(["--root", str(root), "--fix"])
    captured = capsys.readouterr()

    assert code == 2
    assert "Claude Code appears to be running" in captured.err
    assert "--force" in captured.err
    assert "ACTION REQUIRED" in captured.out
    assert AWS_KEY in (root / "session.jsonl").read_text(encoding="utf-8")


def test_force_overrides_active_session_gate(tmp_path, monkeypatch, capsys):
    root = _mkroot(tmp_path)
    monkeypatch.setattr(pipeline, "is_agent_running",
                        lambda markers: (True, "claude.exe"))

    code = main(["--root", str(root), "--fix", "--force"])
    captured = capsys.readouterr()

    assert code == 0
    assert "proceeding while Claude Code appears to be running" in captured.err
    assert AWS_KEY not in (root / "session.jsonl").read_text(encoding="utf-8")


# ----------------------------------------------------------------- redact

def test_fix_redacts_end_to_end_with_force(tmp_path, _no_claude, capsys):
    root = _mkroot(tmp_path)
    code = main(["--root", str(root), "--fix", "--force"])

    assert code == 0
    content = (root / "session.jsonl").read_text(encoding="utf-8")
    assert AWS_KEY not in content
    assert "[REDACTED:aws-access-key]" in content
    assert "[REDACTED:github-pat]" in content
    assert (root / "session.jsonl.bak").exists()


def test_fix_write_error_shows_fail_row_and_exits_2(
        tmp_path, _no_claude, capsys):
    root = _mkroot(tmp_path)
    # Pre-existing .bak makes safe_write refuse — exercises the FAIL row.
    (root / "session.jsonl.bak").write_text("old", encoding="utf-8")

    code = main(["--root", str(root), "--fix", "--force"])
    captured = capsys.readouterr()

    assert code == 2
    assert "FAIL" in captured.err
    assert "Backup already exists" in captured.err
    assert "0/1 file(s) rewritten" in captured.out
    assert AWS_KEY in (root / "session.jsonl").read_text(encoding="utf-8")


def test_fix_no_backup(tmp_path, _no_claude, capsys):
    root = _mkroot(tmp_path)
    code = main(["--root", str(root), "--fix", "--force", "--no-backup"])
    out = capsys.readouterr().out

    assert code == 0
    assert not (root / "session.jsonl.bak").exists()
    assert "no backup" in out
    assert AWS_KEY not in (root / "session.jsonl").read_text(encoding="utf-8")


def test_fix_writes_audit_log_in_isolated_home(
        tmp_path, _isolated_home, _no_claude, capsys):
    root = _mkroot(tmp_path)
    code = main(["--root", str(root), "--fix", "--force"])

    assert code == 0
    audit = _isolated_home / ".agentsweep" / "audit.jsonl"
    assert audit.exists()
    record = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert record["path"].endswith("session.jsonl")


# --------------------------------------------------------- path forgiveness

def test_root_not_found_exits_2_with_suggestion(tmp_path, capsys):
    (tmp_path / "history").mkdir()
    code = main(["--root", str(tmp_path / "histori")])
    captured = capsys.readouterr()

    assert code == 2
    assert "Path not found" in captured.err
    assert "history" in captured.err  # typo suggestion


def test_root_not_found_json_keeps_stdout_parseable(tmp_path, capsys):
    code = main(["--root", str(tmp_path / "nope"), "--json"])
    captured = capsys.readouterr()

    assert code == 2
    assert json.loads(captured.out) == []
    assert "Path not found" in captured.err


# --------------------------------------------------------------- no color

def _force_color(monkeypatch):
    """Make the shared consoles emit color as if on a terminal.

    capsys stdout is not a tty, so rich stays plain by default — force a color
    system on so a no-color regression would actually show escapes to catch.
    """
    monkeypatch.setattr(ui.console, "_color_system", ui.console._color_system
                        or __import__("rich.color", fromlist=["ColorSystem"])
                        .ColorSystem.TRUECOLOR, raising=False)


def test_resolve_no_color_reads_env_and_flag(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert ui.resolve_no_color() is False
    assert ui.resolve_no_color(flag=True) is True

    monkeypatch.setenv("NO_COLOR", "")  # present with any value, per the spec
    assert ui.resolve_no_color() is True

    monkeypatch.setenv("FORCE_COLOR", "1")  # FORCE_COLOR wins over NO_COLOR
    assert ui.resolve_no_color() is False


def test_no_color_env_suppresses_ansi(tmp_path, monkeypatch, capsys):
    _force_color(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "1")
    root = _mkroot(tmp_path)
    code = main(["--root", str(root)])
    out = capsys.readouterr().out

    assert code == 1
    assert "AGENTSWEEP" in out          # human report still rendered
    assert not ANSI_ESCAPE.search(out)  # ...just without escapes


def test_no_color_flag_suppresses_ansi(tmp_path, monkeypatch, capsys):
    _force_color(monkeypatch)
    root = _mkroot(tmp_path)
    code = main(["--root", str(root), "--no-color"])
    out = capsys.readouterr().out

    assert code == 1
    assert "AGENTSWEEP" in out
    assert not ANSI_ESCAPE.search(out)


# ----------------------------------------------------------------- menu

def _feed_menu(monkeypatch, answers: list[str]):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda *a: next(it))


def test_no_args_non_tty_keeps_scan_behavior(tmp_path, _isolated_home, capsys):
    """Pipes/CI must never get the menu — plain scan as before."""
    code = main([])
    captured = capsys.readouterr()
    assert code == 0
    assert "No history files found" in captured.err
    assert "MENU" not in captured.out


def test_menu_renders_and_quits(monkeypatch, _isolated_home, capsys):
    _feed_menu(monkeypatch, ["q"])
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "MENU" in out
    assert "Undo last redaction" in out
    assert "secret scanner for AI agent histories" in out


def test_menu_scan_action_then_quit(monkeypatch, _isolated_home, capsys):
    # Patch _scan_all_sources to avoid traversing real system directories
    # (e.g. APPDATA/Cursor, APPDATA/Windsurf) that are not isolated by tmp_path.
    import sys as _sys
    from agentsweep import menu as _menu
    def _fast_scan_all():
        print("No history files found for any source.", file=_sys.stderr)
    monkeypatch.setattr(_menu, "_scan_all_sources", _fast_scan_all)
    _feed_menu(monkeypatch, ["1", "", "q"])
    assert main([]) == 0
    captured = capsys.readouterr()
    assert "No history files found" in captured.err


def test_menu_folder_typo_then_retry_shows_count(
        tmp_path, monkeypatch, _isolated_home, capsys):
    good = tmp_path / "history"
    good.mkdir()
    (good / "s.jsonl").write_text(FIXTURE_LINE, encoding="utf-8")

    # 2 → typo (suggestion shown) → corrected path (count shown, scan runs)
    # → Enter skips the post-scan redaction offer → Enter → q quit.
    _feed_menu(monkeypatch, ["2", str(tmp_path / "histori"), str(good), "", "",
                             "q"])
    assert main([]) == 0
    captured = capsys.readouterr()

    assert "path not found" in captured.err
    assert "did you mean" in captured.out
    assert "found 1 .jsonl file(s)" in captured.out
    assert "FINDINGS" in captured.out  # the scan actually ran


def test_menu_empty_folder_offers_scan_anyway(
        tmp_path, monkeypatch, _isolated_home, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    # decline the scan-anyway offer twice more → _ask_folder gives up → menu → quit
    _feed_menu(monkeypatch, ["2", str(empty), "n", str(empty), "n", str(empty),
                             "n", "", "q"])
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "found 0 .jsonl file(s)" in out
    assert "scan anyway?" not in out  # prompt text goes via input(), not stdout


def test_menu_invalid_choice_reprompts(monkeypatch, _isolated_home, capsys):
    _feed_menu(monkeypatch, ["0", "q"])
    assert main([]) == 0
    assert "unknown option" in capsys.readouterr().err


def test_menu_redact_requires_typed_confirmation(
        monkeypatch, _isolated_home, _no_claude, capsys):
    fake_root = _isolated_home / ".claude" / "projects"
    fake_root.mkdir(parents=True)
    session = fake_root / "session.jsonl"
    session.write_text(FIXTURE_LINE, encoding="utf-8")

    # "redact" (lowercase) is NOT the magic word — nothing must be written.
    _feed_menu(monkeypatch, ["3", "redact", "", "q"])
    assert main([]) == 0
    assert AWS_KEY in session.read_text(encoding="utf-8")
    assert not session.with_name("session.jsonl.bak").exists()


def test_menu_redact_confirmed_writes_and_undo_restores(
        monkeypatch, _isolated_home, _no_claude, capsys):
    fake_root = _isolated_home / ".claude" / "projects"
    fake_root.mkdir(parents=True)
    session = fake_root / "session.jsonl"
    session.write_text(FIXTURE_LINE, encoding="utf-8")
    original = session.read_text(encoding="utf-8")

    # 3 → REDACT → (mtime gate refuses fresh file → exit 2) → y forces →
    # Enter → 4 undo → y → Enter → q quit.
    _feed_menu(monkeypatch, ["3", "REDACT", "y", "", "4", "y", "", "q"])
    assert main([]) == 0

    restored = session.read_text(encoding="utf-8")
    assert restored == original  # undo brought the secret back, bak consumed
    assert not session.with_name("session.jsonl.bak").exists()


# ----------------------------------------------------- post-scan redaction offer

def test_post_scan_offer_declined_keeps_exit_1(tmp_path, monkeypatch, capsys):
    root = _mkroot(tmp_path)
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    prompts: list[str] = []
    answers = iter([""])

    def fake_input(prompt=""):
        prompts.append(str(prompt))
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    code = main(["--root", str(root)])

    assert code == 1
    assert any("REDACT" in p for p in prompts)  # the offer was made
    assert AWS_KEY in (root / "session.jsonl").read_text(encoding="utf-8")


def test_post_scan_offer_accepted_redacts(
        tmp_path, monkeypatch, _no_claude, capsys):
    root = _mkroot(tmp_path)
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    # Fresh file trips the mtime gate, so the guided --force retry kicks in.
    answers = iter(["REDACT", "y"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))

    code = main(["--root", str(root)])

    assert code == 0
    content = (root / "session.jsonl").read_text(encoding="utf-8")
    assert AWS_KEY not in content
    assert (root / "session.jsonl.bak").exists()


def test_json_mode_never_prompts(tmp_path, monkeypatch, capsys):
    root = _mkroot(tmp_path)
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr(
        "builtins.input",
        lambda *a: (_ for _ in ()).throw(AssertionError("prompted in --json")),
    )
    assert main(["--root", str(root), "--json"]) == 1


# ------------------------------------------------------- graceful shutdown

def _raise_interrupt(*args, **kwargs):
    raise KeyboardInterrupt


def test_ctrl_c_mid_scan_exits_130_no_traceback(tmp_path, monkeypatch, capsys):
    root = _mkroot(tmp_path)
    monkeypatch.setattr(pipeline, "_scan_all", _raise_interrupt)
    code = main(["--root", str(root)])
    captured = capsys.readouterr()

    assert code == 130
    assert "interrupted" in captured.err
    assert "Traceback" not in captured.err


def test_ctrl_c_during_fix_reassures_about_backups(
        tmp_path, monkeypatch, _no_claude, capsys):
    root = _mkroot(tmp_path)
    monkeypatch.setattr(pipeline, "_redact_all", _raise_interrupt)
    code = main(["--root", str(root), "--fix", "--force"])
    captured = capsys.readouterr()

    assert code == 130
    assert "atomic" in captured.err
    assert ".bak" in captured.err


def test_ctrl_c_json_mode_keeps_stdout_clean(tmp_path, monkeypatch, capsys):
    root = _mkroot(tmp_path)
    monkeypatch.setattr(pipeline, "_scan_all", _raise_interrupt)
    code = main(["--root", str(root), "--json"])
    captured = capsys.readouterr()

    assert code == 130
    assert captured.out == ""  # nothing half-emitted on stdout
    assert "interrupted" in captured.err


def test_ctrl_c_at_menu_prompt_exits_gracefully(
        monkeypatch, _isolated_home, capsys):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", _raise_interrupt)
    assert main([]) == 0
    assert "interrupted" in capsys.readouterr().err


# ------------------------------------------------------- encoding fallback

def _console_with_encoding(encoding: str):
    from rich.console import Console
    stream = io.TextIOWrapper(io.BytesIO(), encoding=encoding)
    # legacy_windows=False isolates the stream-encoding probe: on Windows,
    # rich marks any non-terminal stream legacy, which forces ASCII anyway.
    return Console(file=stream, highlight=False, legacy_windows=False)


def test_ascii_fallback_on_cp1252_stream():
    c = _console_with_encoding("cp1252")
    assert ui._icons(c) == ui._ICONS_ASCII
    from rich import box
    assert ui._box(c, box.DOUBLE) is box.ASCII


def test_unicode_icons_on_utf8_stream():
    c = _console_with_encoding("utf-8")
    assert ui._icons(c) == ui._ICONS_UNICODE


def test_scan_progress_is_silent_off_terminal(capsys):
    with ui.scan_progress(5) as progress:
        progress.advance("a.jsonl")
        progress.advance("b.jsonl")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_custom_folder_scan_wires_progress(tmp_path, monkeypatch, capsys):
    """Menu option [3] (--root path) must advance the progress bar once per
    file so large folders show per-file progress instead of hanging silently."""
    root = tmp_path / "history"
    root.mkdir()
    (root / "a.jsonl").write_text('{"message":"hello"}\n', encoding="utf-8")
    (root / "b.jsonl").write_text('{"message":"world"}\n', encoding="utf-8")

    advanced: list[str] = []

    class _TrackingProgress:
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def advance(self, current: str) -> None:
            advanced.append(current)
        def detection(self, *a) -> None:
            pass

    monkeypatch.setattr(ui, "scan_progress", lambda n: _TrackingProgress())

    code = main(["scan", "--root", str(root)])
    assert code == 0
    # One advance() call per file, regardless of the source used.
    assert len(advanced) == 2


def test_safe_escapes_unencodable_path_chars():
    c = _console_with_encoding("cp1252")
    # ✓ (U+2713) cannot encode to cp1252; printing it raw would crash.
    assert "\\u2713" in ui._safe(c, "C:\\Users\\dev\\✓project\\s.jsonl")
    assert ui._safe(c, "plain") == "plain"
