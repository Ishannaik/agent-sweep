"""The in-app contribution nudges: contribute_line + the Star/contribute action."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import __repo__, ui  # noqa: E402
from agentsweep.ui.picker import _ACTION_KEYS, _ACTION_ROWS  # noqa: E402


def test_contribute_line_shows_repo_url(capsys):
    ui.contribute_line()
    out = capsys.readouterr().out
    assert __repo__ in out
    assert "open source" in out.lower()


def test_action_menu_has_star_action():
    assert "star" in _ACTION_KEYS
    assert _ACTION_KEYS[-1] == "quit"  # quit stays last
    assert len(_ACTION_ROWS) == len(_ACTION_KEYS)  # rows/keys stay aligned


def test_json_scan_stays_machine_clean(tmp_path, monkeypatch, capsys):
    # --json output must carry no CTA — the contribution nudge lives only on
    # the human path.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    from agentsweep.cli import main

    empty = tmp_path / "empty"
    empty.mkdir()
    main(["scan", "--root", str(empty), "--json"])
    out = capsys.readouterr().out
    assert __repo__ not in out
    assert "open source" not in out.lower()
