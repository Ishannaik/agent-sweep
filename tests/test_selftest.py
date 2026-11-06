"""Regression coverage for the isolated scanner positive control."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline, selftest  # noqa: E402
from agentsweep.cli import main  # noqa: E402
from agentsweep.ignore import IgnoreSet  # noqa: E402
from agentsweep.sources import ClaudeCodeSource  # noqa: E402
from agentsweep.scanner import RULES  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Isolate user-home source discovery for each selftest case."""

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def _aws_control() -> str:
    """Return an AWS-shaped control without a literal credential fixture."""

    return "AKIA" + "A" * 16


def _history(root: Path) -> Path:
    """Write a minimal Claude JSONL history containing the AWS control."""

    session = root / "session.jsonl"
    session.write_text(
        json.dumps({"message": {"content": [{"type": "text", "text": _aws_control()}]}})
        + "\n",
        encoding="utf-8",
    )
    return session


def test_standalone_selftest_uses_canonical_control_and_cleans_tempdir(
    tmp_path, monkeypatch, capsys, _isolated_home
):
    """Verify the CLI uses and removes a private canonical control corpus."""

    created: list[Path] = []
    real_temporary_directory = tempfile.TemporaryDirectory

    def tracked_temporary_directory(*args, **kwargs):
        """Place and record the temporary corpus so cleanup is observable."""

        kwargs["dir"] = tmp_path
        directory = real_temporary_directory(*args, **kwargs)
        created.append(Path(directory.name))
        return directory

    monkeypatch.setattr(
        selftest.tempfile, "TemporaryDirectory", tracked_temporary_directory
    )

    code = main(["selftest", "--root", str(tmp_path), "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    assert payload["ok"] is True
    assert payload["control"] == "claude-code-jsonl"
    assert {item["rule"] for item in payload["coverage"]} == set(
        selftest.EXPECTED_COUNTS
    )
    assert all(item["status"] == "ok" for item in payload["coverage"])
    assert all(not path.exists() for path in created)
    assert not (_isolated_home / ".agentsweep").exists()
    assert "AKIA" not in captured.out
    assert "sk-ant-" not in captured.out


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong-rule"])
def test_selftest_rejects_missing_duplicate_or_wrong_rule_even_at_same_total(
    tmp_path, monkeypatch, mutation
):
    """Reject count-preserving scans that lose, duplicate, or relabel controls."""

    original_scan_all = pipeline._scan_all

    def altered_scan_all(*args, **kwargs):
        """Inject a count-preserving mutation into the normal scan result."""

        found_by_file, strings, suppressed, truncated = original_scan_all(
            *args, **kwargs
        )
        path = next(iter(found_by_file))
        items = list(found_by_file[path])
        if mutation == "missing":
            found_by_file[path] = [
                item for item in items if item[3].rule != "anthropic"
            ] + [items[1]]
        elif mutation == "duplicate":
            items[1][3].rule = "anthropic"
            found_by_file[path] = items
        else:
            items[0][3].rule = "not-the-expected-rule"
            found_by_file[path] = items
        return found_by_file, strings, suppressed, truncated

    monkeypatch.setattr(pipeline, "_scan_all", altered_scan_all)
    result = selftest.run_selftest(tmp_path)

    assert result.ok is False
    assert sum(result.detected.values()) == sum(result.expected.values())
    assert result.detected != result.expected


@pytest.mark.parametrize("corruption", ["span", "value", "location"])
def test_selftest_rejects_corrupt_metadata_with_correct_rule_counts(
    tmp_path, monkeypatch, corruption
):
    """Reject correct rule counts when a control's metadata is corrupted."""

    original_scan_all = pipeline._scan_all

    def altered_scan_all(*args, **kwargs):
        """Inject one metadata defect while retaining all expected rule counts."""

        found_by_file, strings, suppressed, truncated = original_scan_all(
            *args, **kwargs
        )
        path = next(iter(found_by_file))
        items = list(found_by_file[path])
        line, _keypath, text, finding = items[0]
        if corruption == "span":
            finding.span = (0, 1)
        elif corruption == "value":
            finding.value = "wrong-control-value"
        else:
            wrong_path = path.with_name("wrong-control.jsonl")
            finding.file = wrong_path
            finding.line = line + 1
            finding.keypath = ["wrong", "path"]
            items[0] = (line + 1, ["wrong", "path"], text, finding)
            del found_by_file[path]
            found_by_file[wrong_path] = items
        return found_by_file, strings, suppressed, truncated

    monkeypatch.setattr(pipeline, "_scan_all", altered_scan_all)
    result = selftest.run_selftest(tmp_path)
    coverage = {item["rule"]: item for item in result.as_dict()["coverage"]}

    assert result.ok is False
    assert result.detected == result.expected
    assert coverage["anthropic"]["status"] == "metadata-mismatch"


def test_selftest_fails_closed_without_echoing_scanner_exception(
    tmp_path, monkeypatch, capsys
):
    """Return structured JSON while suppressing scanner exception content."""

    def broken_scan(*args, **kwargs):
        """Raise with control-shaped text to prove it is never emitted."""

        raise RuntimeError("scanner saw " + _aws_control())

    monkeypatch.setattr(pipeline, "_scan_all", broken_scan)

    code = main(["selftest", "--root", str(tmp_path), "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 2
    assert payload["ok"] is False
    assert payload["error_type"] == "RuntimeError"
    assert _aws_control() not in captured.out + captured.err


def test_selftest_fails_closed_when_source_reader_raises(tmp_path, monkeypatch):
    """Fail closed when the canonical source reader cannot read its corpus."""

    def broken_reader(self, path):
        """Act as a failing generator-shaped source reader."""

        raise OSError("unreadable canary")
        yield  # pragma: no cover - establishes this as a generator

    monkeypatch.setattr(ClaudeCodeSource, "iter_strings", broken_reader)

    result = selftest.run_selftest(tmp_path)

    assert result.ok is False
    assert result.error_type == "OSError"


def test_root_and_cwd_ignores_fail_selftest_and_no_ignore_restores_it(
    tmp_path, monkeypatch, capsys
):
    """Apply root and cwd ignores, then prove --no-ignore restores controls."""

    root = tmp_path / "history"
    cwd = tmp_path / "workdir"
    root.mkdir()
    cwd.mkdir()
    (root / ".agentsweepignore").write_text("rule:aws-access-key\n", encoding="utf-8")
    (cwd / ".agentsweepignore").write_text("rule:github-pat\n", encoding="utf-8")
    monkeypatch.chdir(cwd)

    code = main(["selftest", "--root", str(root), "--json"])
    failed = json.loads(capsys.readouterr().out)
    clean_code = main(["selftest", "--root", str(root), "--no-ignore", "--json"])
    clean = json.loads(capsys.readouterr().out)

    assert code == 2
    assert failed["ok"] is False
    assert failed["suppressed"] == 2
    assert clean_code == 0
    assert clean["ok"] is True


def test_selftest_fails_closed_when_cwd_is_unavailable_during_dispatch(
    monkeypatch, capsys
):
    """Return structured failure when dispatch cannot resolve the current directory."""

    def unavailable_cwd():
        """Model a deleted working directory without removing a live directory."""

        raise FileNotFoundError("working directory is unavailable")

    with monkeypatch.context() as cwd_patch:
        cwd_patch.setattr(Path, "cwd", staticmethod(unavailable_cwd))
        code = main(["selftest", "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 2
    assert payload["ok"] is False
    assert payload["error_type"] == "FileNotFoundError"
    assert "Traceback" not in captured.out + captured.err


def test_verify_scanner_blocks_empty_json_scan_before_success(tmp_path, capsys):
    """Block empty scans before success when scanner verification fails."""

    root = tmp_path / "empty"
    root.mkdir()
    (root / ".agentsweepignore").write_text("rule:anthropic\n", encoding="utf-8")

    code = main(["scan", "--root", str(root), "--verify-scanner", "--json"])
    captured = capsys.readouterr()

    assert code == 2
    assert json.loads(captured.out) == []
    assert "Scanner verification failed" in captured.err


def test_verify_scanner_blocks_force_no_backup_before_any_write(
    tmp_path, capsys, _isolated_home
):
    """Prevent forced no-backup redaction before a failed verification can write."""

    root = tmp_path / "history"
    root.mkdir()
    session = _history(root)
    (root / ".agentsweepignore").write_text("rule:anthropic\n", encoding="utf-8")

    code = main(
        [
            "fix",
            "--root",
            str(root),
            "--force",
            "--no-backup",
            "--verify-scanner",
        ]
    )

    assert code == 2
    assert _aws_control() in session.read_text(encoding="utf-8")
    assert not session.with_suffix(".jsonl.bak").exists()
    assert not (_isolated_home / ".agentsweep").exists()
    assert "Scanner verification failed" in capsys.readouterr().err


def test_verify_scanner_blocks_cached_redaction_before_any_write(tmp_path):
    """Prevent cached findings from being redacted after failed verification."""

    root = tmp_path / "history"
    root.mkdir()
    session = _history(root)
    (root / ".agentsweepignore").write_text("rule:anthropic\n", encoding="utf-8")
    source = ClaudeCodeSource(root=root)
    found_by_file, _, _, _ = pipeline._scan_all(
        source, list(source.iter_files()), IgnoreSet()
    )
    args = SimpleNamespace(
        source="claude-code",
        verify_scanner=True,
        no_ignore=False,
        json=False,
        force=True,
        no_backup=True,
        allow_production=True,
    )

    code = pipeline.redact_findings(args, source, found_by_file)

    assert code == 2
    assert _aws_control() in session.read_text(encoding="utf-8")
    assert not session.with_suffix(".jsonl.bak").exists()


def test_selftest_rule_selection_exercises_only_active_controls(tmp_path):
    """Exercise only controls selected by the explicit inclusion filter."""

    result = selftest.run_selftest(
        tmp_path,
        only_rules={"aws-access-key", "github-pat"},
    )
    coverage = {item["rule"]: item for item in result.as_dict()["coverage"]}

    assert result.ok is True
    assert result.expected == {"aws-access-key": 1, "github-pat": 1}
    assert coverage["aws-access-key"]["status"] == "ok"
    assert coverage["github-pat"]["status"] == "ok"
    assert coverage["anthropic"]["status"] == "skipped-by-rule-filter"
    assert coverage["bip39-mnemonic"]["status"] == "skipped-by-rule-filter"


def test_selftest_rejects_rule_selection_without_a_control(tmp_path, capsys):
    """Return a failed coverage payload when selected rules have no control."""

    uncovered_rule = next(
        rule_id
        for rule_id, _display, _pattern in RULES
        if rule_id not in selftest.EXPECTED_COUNTS
    )

    code = main(["selftest", "--only-rule", uncovered_rule, "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert payload["ok"] is False
    assert payload["selection_error"] is not None
    assert {item["status"] for item in payload["coverage"]} == {
        "skipped-by-rule-filter"
    }


def test_selftest_fails_closed_on_scan_warning(tmp_path, monkeypatch):
    """Fail closed when the pipeline reports truncated or unreadable scan input."""

    original_scan_all = pipeline._scan_all

    def truncated_scan(*args, **kwargs):
        """Return a pipeline result marked as truncated."""

        found_by_file, strings, suppressed, _ = original_scan_all(*args, **kwargs)
        return found_by_file, strings, suppressed, [tmp_path / "truncated.jsonl"]

    monkeypatch.setattr(pipeline, "_scan_all", truncated_scan)

    result = selftest.run_selftest(tmp_path)

    assert result.ok is False
    assert result.error_type == "ScanWarning"
