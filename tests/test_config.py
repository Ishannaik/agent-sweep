"""Tests for the optional agentsweep.toml / .agentsweeprc config file.

Covers:
  - config.load_config() precedence (project file over user file) and the
    forbidden-key guard
  - cli._parse_run() merging config values in for --source/--no-color/
    --format/--no-ignore, with CLI flags always winning
  - malformed config never crashes parsing
"""

from __future__ import annotations

import argparse
import json as json_mod
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import cli  # noqa: E402
from agentsweep import config as config_mod  # noqa: E402
from agentsweep.cli import _parse_run  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    return workdir


def _write_project_config(
    workdir: Path, text: str, filename: str = "agentsweep.toml"
) -> Path:
    path = workdir / filename
    path.write_text(text, encoding="utf-8")
    return path


def _write_user_config(home: Path, text: str) -> Path:
    cfg_dir = home / ".config" / "agentsweep"
    cfg_dir.mkdir(parents=True)
    path = cfg_dir / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


class TestLoadConfig:
    def test_no_file_returns_empty(self):
        assert config_mod.load_config() == {}

    def test_project_file_read(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'source = "codex"\n')
        assert config_mod.load_config() == {"source": "codex"}

    def test_agentsweeprc_alt_filename(self, _isolated_cwd):
        _write_project_config(
            _isolated_cwd, "no_color = true\n", filename=".agentsweeprc"
        )
        assert config_mod.load_config() == {"no_color": True}

    def test_project_file_wins_over_user_file(self, _isolated_cwd, _isolated_home):
        _write_user_config(_isolated_home, 'source = "aider"\n')
        _write_project_config(_isolated_cwd, 'source = "codex"\n')
        assert config_mod.load_config() == {"source": "codex"}

    def test_user_file_used_when_no_project_file(self, _isolated_home):
        _write_user_config(_isolated_home, 'source = "aider"\n')
        assert config_mod.load_config() == {"source": "aider"}

    def test_unknown_key_ignored(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'made_up_flag = "x"\nsource = "codex"\n')
        assert config_mod.load_config() == {"source": "codex"}

    def test_forbidden_keys_never_returned(self, _isolated_cwd, capsys):
        _write_project_config(
            _isolated_cwd,
            'allow_production = true\nforce = true\nno_backup = true\nsource = "codex"\n',
        )
        result = config_mod.load_config()
        assert result == {"source": "codex"}
        assert "allow_production" not in result
        assert "force" not in result
        assert "no_backup" not in result
        err = capsys.readouterr().err
        assert "allow_production" in err
        assert "force" in err
        assert "no_backup" in err

    def test_malformed_toml_does_not_raise(self, _isolated_cwd, capsys):
        _write_project_config(_isolated_cwd, "this is not [ valid toml")
        assert config_mod.load_config() == {}
        assert "warning" in capsys.readouterr().err

    def test_string_no_color_is_rejected_not_coerced(self, _isolated_cwd, capsys):
        # bool("false") is True in Python — a string value must never reach
        # args.no_color, or it silently inverts the user's intent.
        _write_project_config(_isolated_cwd, 'no_color = "false"\n')
        result = config_mod.load_config()
        assert "no_color" not in result
        assert "no_color" in capsys.readouterr().err

    def test_string_no_ignore_is_rejected_not_coerced(self, _isolated_cwd, capsys):
        _write_project_config(_isolated_cwd, 'no_ignore = "false"\n')
        result = config_mod.load_config()
        assert "no_ignore" not in result
        assert "no_ignore" in capsys.readouterr().err

    def test_non_string_source_is_rejected(self, _isolated_cwd, capsys):
        _write_project_config(_isolated_cwd, "source = 42\n")
        result = config_mod.load_config()
        assert "source" not in result
        assert "source" in capsys.readouterr().err

    def test_type_mismatch_warning_never_echoes_the_value(self, _isolated_cwd, capsys):
        # agentsweep redacts secrets; a mistyped config line must not get its
        # content printed to stderr on every run. no_color expects a bool, so
        # a string value here triggers the type-mismatch warning path.
        secret_looking_value = "AKIAIOSFODNN7EXAMPLE"
        _write_project_config(_isolated_cwd, f'no_color = "{secret_looking_value}"\n')
        config_mod.load_config()
        err = capsys.readouterr().err
        assert secret_looking_value not in err
        assert "no_color" in err
        assert "str" in err

    def test_valid_bool_no_color_still_applies(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, "no_color = false\n")
        assert config_mod.load_config() == {"no_color": False}


class TestParseRunMergesConfig:
    def test_source_from_config_applies_when_flag_omitted(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'source = "codex"\n')
        args = _parse_run("scan", [])
        assert args.source == "codex"

    def test_cli_flag_overrides_config_source(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'source = "codex"\n')
        args = _parse_run("scan", ["--source", "claude-code"])
        assert args.source == "claude-code"

    def test_config_source_does_not_conflict_with_all(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'source = "codex"\n')
        args = _parse_run("scan", ["--all"])
        assert args.all is True
        assert args.source == "claude-code"

    def test_no_color_from_config(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, "no_color = true\n")
        args = _parse_run("scan", [])
        assert args.no_color is True

    def test_no_color_defaults_false_without_config_or_flag(self):
        args = _parse_run("scan", [])
        assert args.no_color is False

    def test_no_ignore_from_config(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, "no_ignore = true\n")
        args = _parse_run("scan", [])
        assert args.no_ignore is True

    def test_ignore_flag_overrides_config_no_ignore(self, _isolated_cwd):
        # no_ignore=true in config is otherwise a one-way door with no CLI
        # route back to the built-in default (there's no bare --ignore-less
        # way to force it False) — --ignore is that route.
        _write_project_config(_isolated_cwd, "no_ignore = true\n")
        args = _parse_run("scan", ["--ignore"])
        assert args.no_ignore is False

    def test_format_from_config(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'format = "sarif"\n')
        args = _parse_run("scan", [])
        assert args.format == "sarif"

    def test_config_format_does_not_conflict_with_fix(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'format = "sarif"\n')
        args = _parse_run("fix", [])
        assert args.fix is True
        assert args.format is None

    def test_config_format_does_not_conflict_with_json(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'format = "sarif"\n')
        args = _parse_run("scan", ["--json"])
        assert args.json is True
        assert args.format is None

    def test_config_format_does_not_conflict_with_report(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'format = "sarif"\n')
        args = _parse_run("scan", ["--report"])
        assert args.report is True
        assert args.format is None
        # --report always implies JSON output regardless of the config file.
        assert args.json is True

    def test_format_human_overrides_config_sarif(self, _isolated_cwd):
        # format="sarif" in config is otherwise a one-way door: choices are
        # ["sarif"] only downstream, so there was no CLI route back to the
        # human report on a plain `scan`. --format human is that route.
        _write_project_config(_isolated_cwd, 'format = "sarif"\n')
        args = _parse_run("scan", ["--format", "human"])
        assert args.format is None

    def test_invalid_source_in_config_errors(self, _isolated_cwd):
        _write_project_config(_isolated_cwd, 'source = "not-a-real-source"\n')
        with pytest.raises(SystemExit):
            _parse_run("scan", [])

    def test_forbidden_keys_in_config_never_set_args(self, _isolated_cwd):
        _write_project_config(
            _isolated_cwd,
            "allow_production = true\nforce = true\nno_backup = true\n",
        )
        args = _parse_run("fix", [])
        assert args.allow_production is False
        assert args.force is False
        assert args.no_backup is False


class TestUpdateNoticeSkipsConfigSarif:
    """format="sarif" is machine-readable output just like --json, and the
    update-available banner must not get interleaved into it on a tty run
    where the user never passed --json."""

    def test_update_notice_skipped_when_format_is_sarif(self, monkeypatch, capsys):
        import urllib.request

        class _FakeResp:
            def read(self):
                return json_mod.dumps({"info": {"version": "99.0.0"}}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.delenv("AGENTSWEEP_NO_UPDATE", raising=False)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _FakeResp())

        args = argparse.Namespace(json=False, format="sarif")
        cli._background_update_notice(args)
        out = capsys.readouterr().out

        assert "agentsweep 99.0.0 available" not in out
