"""Tests for the `agentsweep list-sources` verb (cli.py / pipeline.py).

Covers:
  (a) list-sources --json → parseable list, one entry per registered source,
      required keys present and correctly typed, exit 0
  (b) every SOURCES key appears exactly once in the JSON payload
  (c) --detected filters to only sources whose root exists (subset of full)
  (d) detection tracks the on-disk root: claude-code flips False→True once its
      default root is created under an isolated HOME
  (e) human (non-JSON) output renders without crashing and exits 0
  (f) list-sources exits before any scan — no findings/pipeline output leaks
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import main  # noqa: E402
from agentsweep.sources import SOURCES  # noqa: E402


# ---------------------------------------------------------------------------
# Isolate HOME / USERPROFILE so HOME-rooted sources (claude-code, codex, …)
# don't report detection based on the real machine.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    yield fake_home


# ===========================================================================
# (a) / (b) JSON output shape
# ===========================================================================


def test_list_sources_json_lists_every_source(capsys):
    code = main(["list-sources", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    keys = [row["source"] for row in payload]
    # Exactly one entry per registered source, no dupes, no omissions.
    assert keys == list(SOURCES)
    assert len(keys) == len(set(keys))


def test_list_sources_json_entry_schema(capsys):
    main(["list-sources", "--json"])
    payload = json.loads(capsys.readouterr().out)
    for row in payload:
        assert set(row) == {"source", "display", "experimental", "root", "detected"}
        assert isinstance(row["source"], str) and row["source"]
        assert isinstance(row["display"], str) and row["display"]
        assert isinstance(row["experimental"], bool)
        assert isinstance(row["root"], str)
        assert isinstance(row["detected"], bool)


# ===========================================================================
# (c) --detected filters to a subset
# ===========================================================================


def test_detected_flag_is_subset_of_all(capsys):
    main(["list-sources", "--json"])
    full = json.loads(capsys.readouterr().out)
    main(["list-sources", "--json", "--detected"])
    detected = json.loads(capsys.readouterr().out)

    assert all(row["detected"] for row in detected)
    full_keys = {row["source"] for row in full}
    detected_keys = {row["source"] for row in detected}
    assert detected_keys <= full_keys
    # The detected set is exactly the detected rows of the full set.
    assert detected_keys == {row["source"] for row in full if row["detected"]}


# ===========================================================================
# (d) detection tracks the on-disk root
# ===========================================================================


def test_detection_reflects_root_existence(_isolate_home, capsys):
    def _claude_row():
        main(["list-sources", "--json"])
        payload = json.loads(capsys.readouterr().out)
        return next(r for r in payload if r["source"] == "claude-code")

    # Root absent under the isolated HOME → not detected.
    assert _claude_row()["detected"] is False

    # Create the default root; detection should flip to True.
    (_isolate_home / ".claude" / "projects").mkdir(parents=True)
    assert _claude_row()["detected"] is True


# ===========================================================================
# (e) human output renders and exits 0
# ===========================================================================


def test_list_sources_human_output_exits_0(capsys):
    code = main(["list-sources"])
    out = capsys.readouterr().out
    assert code == 0
    # Banner + at least one source key should appear in the rendered table.
    assert "claude-code" in out


def test_list_sources_human_detected_only_exits_0(_isolate_home, capsys):
    (_isolate_home / ".claude" / "projects").mkdir(parents=True)
    code = main(["list-sources", "--detected"])
    assert code == 0
    assert "claude-code" in capsys.readouterr().out


# ===========================================================================
# (f) list-sources never scans
# ===========================================================================


def test_list_sources_does_not_scan(capsys):
    """No 'FINDINGS' / 'SCAN' pipeline stages should appear — it lists only."""
    main(["list-sources"])
    out = capsys.readouterr().out
    assert "FINDINGS" not in out
    assert "SECRET (masked)" not in out
