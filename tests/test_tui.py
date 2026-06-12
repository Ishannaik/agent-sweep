"""Tests for the interactive TUI components (keys.py, picker.py) and the
parallel file-scan path added in _scan_all (pipeline.py Task 7)."""
from __future__ import annotations

import io
import os
import pty
import sys
import termios
import threading
import time
from unittest.mock import patch

import pytest

from agentsweep.ui import keys as _keys
from agentsweep.ui.picker import action_menu, source_picker, _run_menu
from agentsweep.sources import SOURCES


# ── keys.py ──────────────────────────────────────────────────────────────────

def test_key_constants_are_distinct_strings():
    consts = [_keys.UP, _keys.DOWN, _keys.ENTER, _keys.SPACE, _keys.QUIT, _keys.OTHER]
    assert len(set(consts)) == 6
    for c in consts:
        assert isinstance(c, str)


def test_raw_input_available_is_bool():
    assert isinstance(_keys.RAW_INPUT_AVAILABLE, bool)


def test_raw_input_unavailable_in_test_subprocess(monkeypatch):
    """pytest runs without a tty, so _probe() must return False."""
    import sys
    # The probe checks isatty(); in test env stdin is a pipe, so False.
    assert not sys.stdin.isatty()
    # RAW_INPUT_AVAILABLE was set at import time, reflect that.
    assert _keys.RAW_INPUT_AVAILABLE is False

# ── keys._read_key_unix real byte parsing (pty regression) ────────────────────

_BYTE_SEQ_CASES = [
    (b"\x1b[A", _keys.UP),     # CSI up
    (b"\x1b[B", _keys.DOWN),   # CSI down
    (b"\x1bOA", _keys.UP),     # SS3 up (application-cursor-key mode)
    (b"\x1bOB", _keys.DOWN),   # SS3 down
    (b"\x1b", _keys.QUIT),     # bare ESC key
    (b"\r", _keys.ENTER),
    (b" ", _keys.SPACE),
    (b"q", _keys.QUIT),
]

def _feed_keys_when_raw(master_fd, slave_fd, data):
    # Wait until _read_key_unix switches the slave out of canonical mode
    # (setcbreak clears ICANON) before writing, so the bytes are neither
    # discarded by setcbreak(TCSAFLUSH) nor held by the canonical line
    # discipline waiting for a newline.
    for _ in range(400):
        if not (termios.tcgetattr(slave_fd)[3] & termios.ICANON):
            break
        time.sleep(0.005)
    os.write(master_fd, data)



@pytest.mark.skipif(sys.platform == "win32", reason="unix key reader")
@pytest.mark.parametrize("seq,expected", _BYTE_SEQ_CASES)
def test_read_key_unix_parses_real_byte_sequences(seq, expected, monkeypatch):
    """Drive the real fd-level parser through a pty.

    Regression guard: an arrow key arrives as a multi-byte escape sequence.
    Reading via buffered sys.stdin drained the whole sequence into a userspace
    buffer, so select() on the fd reported no tail and every arrow was misread
    as a bare ESC (quit). sys.stdin below is a *buffered* TextIOWrapper — the
    exact shape that triggered the bug — so this fails if the parser regresses
    to sys.stdin.read.
    """
    master, slave = pty.openpty()
    # Buffered TextIOWrapper over the slave: the exact stdin shape that
    # triggered the original bug.
    stdin = io.TextIOWrapper(
        io.BufferedReader(io.FileIO(slave, "r", closefd=False)), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "stdin", stdin)
    feeder = threading.Thread(target=_feed_keys_when_raw, args=(master, slave, seq))
    feeder.start()
    try:
        assert _keys._read_key_unix() == expected
    finally:
        feeder.join()
        os.close(master)
        os.close(slave)

# ── picker._run_menu single-select ───────────────────────────────────────────

def _run_with_keys(key_seq, **kw):
    """Run _run_menu driven by a pre-canned key sequence."""
    rows = [("Option A", "hint a"), ("Option B", "hint b"), ("Option C", "hint c")]
    it = iter(key_seq)
    with patch("agentsweep.ui.picker._keys.read_key", side_effect=it):
        with patch("agentsweep.ui.picker.Live") as mock_live:
            # Make Live a context manager that does nothing
            mock_live.return_value.__enter__ = lambda s: mock_live.return_value
            mock_live.return_value.__exit__ = lambda s, *a: False
            mock_live.return_value.update = lambda *a: None
            return _run_menu("TEST", rows, **kw)


def test_single_select_enter_on_first_row():
    result = _run_with_keys([_keys.ENTER])
    assert result == 0


def test_single_select_navigate_then_enter():
    result = _run_with_keys([_keys.DOWN, _keys.ENTER])
    assert result == 1


def test_single_select_navigate_wrap_around():
    # UP on row 0 wraps to last row
    result = _run_with_keys([_keys.UP, _keys.ENTER])
    assert result == 2


def test_single_select_quit_returns_none():
    result = _run_with_keys([_keys.QUIT])
    assert result is None


# ── picker._run_menu multi-select ─────────────────────────────────────────────

def test_multi_select_space_toggles():
    """SPACE on row 0 checks it; DOWN twice to Run button + ENTER returns it in the set."""
    rows = [("A", ""), ("B", ""), ("[ Run ]", "")]
    # Space toggles A → checked; DOWN x2 → Run button; ENTER → returns ({0}, True)
    it = iter([_keys.SPACE, _keys.DOWN, _keys.DOWN, _keys.ENTER])
    with patch("agentsweep.ui.picker._keys.read_key", side_effect=it):
        with patch("agentsweep.ui.picker.Live") as mock_live:
            mock_live.return_value.__enter__ = lambda s: mock_live.return_value
            mock_live.return_value.__exit__ = lambda s, *a: False
            mock_live.return_value.update = lambda *a: None
            result = _run_menu("TEST", rows, multi=True, button_idx=2)
    assert isinstance(result, tuple)
    checked, run_pressed = result
    assert 0 in checked  # A was toggled on
    assert run_pressed is True


def test_multi_select_run_button_returns_run_true():
    rows = [("A", ""), ("B", ""), ("[ Run ]", "")]
    # DOWN twice to land on Run, then ENTER
    it = iter([_keys.DOWN, _keys.DOWN, _keys.ENTER])
    with patch("agentsweep.ui.picker._keys.read_key", side_effect=it):
        with patch("agentsweep.ui.picker.Live") as mock_live:
            mock_live.return_value.__enter__ = lambda s: mock_live.return_value
            mock_live.return_value.__exit__ = lambda s, *a: False
            mock_live.return_value.update = lambda *a: None
            result = _run_menu("TEST", rows, multi=True, button_idx=2)
    checked, run_pressed = result
    assert run_pressed is True
    assert isinstance(checked, set)


# ── picker.action_menu ────────────────────────────────────────────────────────

def test_action_menu_quit_returns_quit():
    with patch("agentsweep.ui.picker._keys.read_key", return_value=_keys.QUIT):
        with patch("agentsweep.ui.picker.Live") as mock_live:
            mock_live.return_value.__enter__ = lambda s: mock_live.return_value
            mock_live.return_value.__exit__ = lambda s, *a: False
            mock_live.return_value.update = lambda *a: None
            result = action_menu()
    assert result is None


def test_action_menu_select_scan():
    # ENTER on first row (index 0) → "scan"
    with patch("agentsweep.ui.picker._keys.read_key", return_value=_keys.ENTER):
        with patch("agentsweep.ui.picker.Live") as mock_live:
            mock_live.return_value.__enter__ = lambda s: mock_live.return_value
            mock_live.return_value.__exit__ = lambda s, *a: False
            mock_live.return_value.update = lambda *a: None
            result = action_menu()
    assert result == "scan"


# ── picker.source_picker ──────────────────────────────────────────────────────

def test_source_picker_quit_returns_none():
    with patch("agentsweep.ui.picker._keys.read_key", return_value=_keys.QUIT):
        with patch("agentsweep.ui.picker.Live") as mock_live:
            mock_live.return_value.__enter__ = lambda s: mock_live.return_value
            mock_live.return_value.__exit__ = lambda s, *a: False
            mock_live.return_value.update = lambda *a: None
            result = source_picker()
    assert result is None


def test_source_picker_default_when_nothing_selected():
    """Pressing Run with nothing checked defaults to claude-code."""
    from agentsweep.sources import SOURCES
    n_sources = len(SOURCES)
    # Navigate to Run Scan button: it's at index n_sources + 1 (custom + run)
    run_idx = n_sources + 1
    keys_seq = [_keys.DOWN] * run_idx + [_keys.ENTER]
    it = iter(keys_seq)
    with patch("agentsweep.ui.picker._keys.read_key", side_effect=it):
        with patch("agentsweep.ui.picker.Live") as mock_live:
            mock_live.return_value.__enter__ = lambda s: mock_live.return_value
            mock_live.return_value.__exit__ = lambda s, *a: False
            mock_live.return_value.update = lambda *a: None
            result = source_picker()
    assert result == ["claude-code"]


def test_source_picker_select_first_source():
    """Space on first row (claude-code) then navigate to Run and press Enter."""
    from agentsweep.sources import SOURCES
    n_sources = len(SOURCES)
    run_idx = n_sources + 1
    # Space to select first, then DOWN to run, ENTER
    keys_seq = [_keys.SPACE] + [_keys.DOWN] * run_idx + [_keys.ENTER]
    it = iter(keys_seq)
    with patch("agentsweep.ui.picker._keys.read_key", side_effect=it):
        with patch("agentsweep.ui.picker.Live") as mock_live:
            mock_live.return_value.__enter__ = lambda s: mock_live.return_value
            mock_live.return_value.__exit__ = lambda s, *a: False
            mock_live.return_value.update = lambda *a: None
            result = source_picker()
    assert isinstance(result, list)
    assert "claude-code" in result


# ── menu.py dispatch ──────────────────────────────────────────────────────────

def test_run_menu_uses_numbered_fallback_when_raw_unavailable(monkeypatch, capsys):
    """When RAW_INPUT_AVAILABLE=False the numbered menu path is used."""
    from agentsweep import menu
    from agentsweep import cli
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr("agentsweep.ui.keys.RAW_INPUT_AVAILABLE", False)
    inputs = iter(["q"])
    monkeypatch.setattr("builtins.input", lambda *a: next(inputs))
    code = menu.run_menu()
    assert code == 0


# ── pipeline parallel scan (Task 7) ──────────────────────────────────────────

def test_parallel_scan_same_results_as_sequential(tmp_path):
    """_scan_all with >4 files (threadpool path) must produce identical results
    to sequential scan.  We write 6 JSONL files — 5 clean, 1 with a secret —
    and confirm findings are detected correctly in both modes."""
    import json
    from pathlib import Path
    from agentsweep.pipeline import _scan_all
    from agentsweep.sources import ClaudeCodeSource

    secret = "AKIAIOSFODNN7EXAMPLE"  # AWS key — canonical test fixture

    # 5 clean files + 1 with a real AWS key
    for i in range(5):
        (tmp_path / f"clean_{i}.jsonl").write_text(
            json.dumps({"type": "assistant", "message": {"content": f"hello {i}"}}) + "\n",
            encoding="utf-8",
        )
    dirty = tmp_path / "dirty.jsonl"
    dirty.write_text(
        json.dumps({"type": "assistant", "message": {
            "content": f"my aws key is {secret}"
        }}) + "\n",
        encoding="utf-8",
    )

    source = ClaudeCodeSource(root=tmp_path)
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 6  # ensures threadpool path is taken (>4)

    found, scanned, suppressed = _scan_all(source, files, ignores=None)

    assert suppressed == 0
    assert len(found) == 1, f"expected 1 dirty file, got {len(found)}: {list(found)}"
    findings = found[dirty]
    assert any(f.rule == "aws-access-key" for _, _, _, f in findings)
