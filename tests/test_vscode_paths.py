"""Cross-platform default_root() coverage for the VS Code-fork sources.

CI runs each OS branch of the path resolver only on the runner that hosts
it. These tests force win32 / darwin / linux from a single run by patching
sys.platform and the relevant env vars, with HOME pointed at tmp_path so
nothing resolves against the real home directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.sources import (  # noqa: E402
    CursorSource,
    PearAiSource,
    TraeSource,
    VoidSource,
    WindsurfSource,
)

# (source class, path of its root below the per-OS base dir)
VSCODE_FORKS = [
    (CursorSource, ("Cursor", "User")),
    (WindsurfSource, ("Windsurf", "User")),
    (TraeSource, ("Trae", "User")),
    (VoidSource, ("Void", "User")),
    (
        PearAiSource,
        ("PearAI", "User", "globalStorage", "PearAI.pearai-roo-cline"),
    ),
]
IDS = [cls.__name__ for cls, _ in VSCODE_FORKS]


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return home


@pytest.mark.parametrize(("source_cls", "tail"), VSCODE_FORKS, ids=IDS)
def test_win32_uses_appdata(source_cls, tail, home, tmp_path, monkeypatch):
    appdata = tmp_path / "AppData" / "Roaming"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(appdata))

    assert source_cls.default_root() == appdata.joinpath(*tail)


@pytest.mark.parametrize(("source_cls", "tail"), VSCODE_FORKS, ids=IDS)
def test_darwin_uses_application_support(source_cls, tail, home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    # XDG_CONFIG_HOME must not leak into the macOS layout.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))

    expected = home / "Library" / "Application Support"
    assert source_cls.default_root() == expected.joinpath(*tail)


@pytest.mark.parametrize(("source_cls", "tail"), VSCODE_FORKS, ids=IDS)
def test_linux_honors_xdg_config_home(source_cls, tail, home, tmp_path, monkeypatch):
    xdg = tmp_path / "xdg-config"
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))

    assert source_cls.default_root() == xdg.joinpath(*tail)


@pytest.mark.parametrize("xdg_value", [None, ""], ids=["unset", "empty"])
@pytest.mark.parametrize(("source_cls", "tail"), VSCODE_FORKS, ids=IDS)
def test_linux_falls_back_to_dot_config(source_cls, tail, xdg_value, home, monkeypatch):
    # Regression: Path("") is Path(".") and truthy, so an `or` fallback on it
    # never fired and Cursor/Windsurf resolved to a cwd-relative "Cursor/User".
    monkeypatch.setattr(sys, "platform", "linux")
    if xdg_value is not None:
        monkeypatch.setenv("XDG_CONFIG_HOME", xdg_value)

    root = source_cls.default_root()

    assert root.is_absolute()
    assert root == (home / ".config").joinpath(*tail)


@pytest.mark.parametrize(("source_cls", "tail"), VSCODE_FORKS, ids=IDS)
def test_win32_without_appdata_falls_back_to_dot_config(
    source_cls, tail, home, monkeypatch
):
    monkeypatch.setattr(sys, "platform", "win32")

    assert source_cls.default_root() == (home / ".config").joinpath(*tail)
