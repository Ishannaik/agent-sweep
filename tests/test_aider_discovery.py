"""Aider discovery: prune junk dirs, depth cap, and honest detection.

Default Aider root is $HOME. Unbounded rglob thrashed real machines and made
list-sources always report Aider as present. These tests stay under tmp_path.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import main  # noqa: E402
from agentsweep.sources._core import (  # noqa: E402
    AiderSource,
    _AIDER_HISTORY_NAME,
    _AIDER_MAX_DEPTH,
    _iter_aider_histories,
)


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    yield fake_home


def _write_history(path: Path, body: str = "# aider chat\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_finds_history_under_project_root(tmp_path: Path) -> None:
    root = tmp_path / "work"
    hist = _write_history(root / "proj" / _AIDER_HISTORY_NAME)
    found = list(AiderSource(root=root).files())
    assert found == [hist]


def test_skips_node_modules_and_git(tmp_path: Path) -> None:
    root = tmp_path / "work"
    real = _write_history(root / "proj" / _AIDER_HISTORY_NAME)
    decoy_nm = _write_history(
        root / "proj" / "node_modules" / "pkg" / _AIDER_HISTORY_NAME,
        "# decoy in node_modules\n",
    )
    decoy_git = _write_history(
        root / "proj" / ".git" / "objects" / _AIDER_HISTORY_NAME,
        "# decoy in .git\n",
    )
    found = set(AiderSource(root=root).files())
    assert real in found
    assert decoy_nm not in found
    assert decoy_git not in found


def test_prunes_os_profile_dirs_directly_under_home(_isolate_home: Path) -> None:
    # Default root is $HOME: AppData/Library/.local/.Trash directly under it
    # are OS-profile junk and must be pruned.
    home = _isolate_home
    real = _write_history(home / "Projects" / "app" / _AIDER_HISTORY_NAME)
    decoy_app = _write_history(home / "AppData" / "Local" / "j" / _AIDER_HISTORY_NAME)
    decoy_lib = _write_history(home / "Library" / "Caches" / "j" / _AIDER_HISTORY_NAME)
    decoy_local = _write_history(home / ".local" / "share" / "j" / _AIDER_HISTORY_NAME)
    found = set(AiderSource().files())
    assert real in found
    assert decoy_app not in found
    assert decoy_lib not in found
    assert decoy_local not in found


def test_os_profile_named_project_dir_is_scanned(tmp_path: Path) -> None:
    # A *project* named "Library"/"AppData" that is NOT a direct child of $HOME
    # is a real repo and must be scanned — the old flat skip-set dropped it,
    # silently hiding any secret inside (regression this PR's fix repairs).
    root = tmp_path / "work"
    lib = _write_history(root / "clients" / "Library" / _AIDER_HISTORY_NAME)
    app = _write_history(root / "src" / "AppData" / _AIDER_HISTORY_NAME)
    found = set(AiderSource(root=root).files())
    assert lib in found
    assert app in found


def test_config_dotfiles_history_is_found(_isolate_home: Path) -> None:
    # Dotfiles repos (e.g. ~/.config/nvim) are a real Aider workflow; ~/.config
    # must be walked, not blanket-pruned. Previously silently missed.
    home = _isolate_home
    hist = _write_history(home / ".config" / "nvim" / _AIDER_HISTORY_NAME)
    found = set(AiderSource().files())
    assert hist in found


def test_depth_cap_stops_deep_trees(tmp_path: Path) -> None:
    root = tmp_path / "work"
    # depth = number of path parts under root. Nested dirs: d1/d2/.../dN/file
    deep = root
    for i in range(_AIDER_MAX_DEPTH + 3):
        deep = deep / f"d{i}"
    deep_hist = _write_history(deep / _AIDER_HISTORY_NAME)
    shallow = _write_history(root / "proj" / _AIDER_HISTORY_NAME)
    found = set(_iter_aider_histories(root))
    assert shallow in found
    assert deep_hist not in found


def test_depth_cap_is_surfaced_on_scan(tmp_path: Path, capsys) -> None:
    # A reached depth cap must NOT be silent (project rule): scan path warns.
    root = tmp_path / "work"
    deep = root
    for i in range(_AIDER_MAX_DEPTH + 2):
        deep = deep / f"d{i}"
    _write_history(deep / _AIDER_HISTORY_NAME)
    list(_iter_aider_histories(root, warn=True))
    err = capsys.readouterr().err
    assert "depth cap" in err
    assert "--root" in err


def test_depth_cap_silent_during_detection(tmp_path: Path, capsys) -> None:
    # warn=False (detection / list-sources) must print nothing.
    root = tmp_path / "work"
    deep = root
    for i in range(_AIDER_MAX_DEPTH + 2):
        deep = deep / f"d{i}"
    _write_history(deep / _AIDER_HISTORY_NAME)
    list(_iter_aider_histories(root, warn=False))
    assert capsys.readouterr().err == ""


def test_is_detected_false_on_empty_home(_isolate_home: Path) -> None:
    src = AiderSource()
    assert src.root == _isolate_home
    assert src.is_detected() is False


def test_is_detected_true_when_history_exists(_isolate_home: Path) -> None:
    _write_history(_isolate_home / "code" / "repo" / _AIDER_HISTORY_NAME)
    # Junk trees that would have made old rglob expensive.
    (_isolate_home / "node_modules" / "x").mkdir(parents=True)
    (_isolate_home / ".git" / "objects").mkdir(parents=True)
    assert AiderSource().is_detected() is True


def test_is_detected_true_from_config_marker(_isolate_home: Path) -> None:
    (_isolate_home / ".aider.conf.yml").write_text("model: gpt\n", encoding="utf-8")
    assert AiderSource().is_detected() is True


def test_list_sources_aider_detection_tracks_history(
    _isolate_home: Path, capsys,
) -> None:
    def _aider_row():
        main(["list-sources", "--json"])
        payload = json.loads(capsys.readouterr().out)
        return next(r for r in payload if r["source"] == "aider")

    assert _aider_row()["detected"] is False
    _write_history(_isolate_home / "proj" / _AIDER_HISTORY_NAME)
    assert _aider_row()["detected"] is True
