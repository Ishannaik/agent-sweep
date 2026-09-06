"""The .pre-commit-hooks.yaml manifest and the CLI contract it relies on.

`pre-commit try-repo` needs pre-commit installed and builds a venv, so it is
not run here. Instead: validate the manifest structurally, and assert the
exit-code contract the hook depends on (0 clean / no sources, 1 with a secret)
directly through the CLI.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline  # noqa: E402
from agentsweep.cli import main  # noqa: E402

_MANIFEST = Path(__file__).resolve().parent.parent / ".pre-commit-hooks.yaml"
_SECRET = (
    '{"type":"user","message":{"content":'
    '[{"type":"text","text":"key=AKIAIOSFODNN7EXAMPLE"}]}}\n'
)


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg" / "config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("AGENTSWEEP_NO_UPDATE", "1")
    monkeypatch.delenv("GROK_HOME", raising=False)
    return home


@pytest.fixture(autouse=True)
def _no_agent_running(monkeypatch):
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))


def _seed_claude(home: Path) -> Path:
    d = home / ".claude" / "projects" / "proj"
    d.mkdir(parents=True)
    f = d / "session.jsonl"
    f.write_text(_SECRET, encoding="utf-8")
    past = time.time() - 3700
    os.utime(f, (past, past))
    return f


def test_manifest_exists():
    assert _MANIFEST.is_file()


def test_manifest_declares_the_hook():
    yaml = pytest.importorskip("yaml")
    hooks = yaml.safe_load(_MANIFEST.read_text(encoding="utf-8"))
    assert isinstance(hooks, list) and len(hooks) == 1
    hook = hooks[0]
    assert hook["id"] == "agentsweep"
    assert hook["entry"] == "agentsweep scan --all --detected"
    assert hook["language"] == "python"
    # Scans history roots, not staged files — must not receive filenames and
    # must run every commit regardless of what changed.
    assert hook["pass_filenames"] is False
    assert hook["always_run"] is True


def test_hook_entry_matches_a_real_console_script():
    # The manifest's entry must be an installed command; pyproject ships it.
    pyproject = (_MANIFEST.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert 'agentsweep = "agentsweep.cli:main"' in pyproject


def test_hook_command_exits_1_on_secret(_isolate_env, capsys):
    _seed_claude(_isolate_env)
    # Exactly what the manifest's `entry` runs.
    code = main(["scan", "--all", "--detected"])
    assert code == 1


def test_hook_command_exits_0_when_clean(_isolate_env, capsys):
    d = _isolate_env / ".claude" / "projects" / "proj"
    d.mkdir(parents=True)
    f = d / "session.jsonl"
    f.write_text('{"type":"user","message":"nothing"}\n', encoding="utf-8")
    past = time.time() - 3700
    os.utime(f, (past, past))

    code = main(["scan", "--all", "--detected"])
    assert code == 0


def test_hook_command_exits_0_when_no_sources_detected(_isolate_env, capsys):
    # Empty machine: --detected finds nothing, so the hook must not block
    # every commit with exit 2.
    code = main(["scan", "--all", "--detected"])
    assert code == 0
