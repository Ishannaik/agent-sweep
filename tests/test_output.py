"""Tests for -o/--output and anti-flood behavior in pipeline.py / cli.py.

Covers:
  (a) scan --json -o FILE  → valid JSON to file, summary to stderr, clean stdout, exit 1
  (b) scan -o FILE (human) → also writes JSON to file
  (c) anti-flood JSON: >30 findings + isatty→True, no -o → writes DEFAULT_JSON_NAME,
      prints summary to stderr, does NOT dump JSON to stdout, exit 1
  (d) anti-flood human: >40 findings + console.is_terminal→True → table capped,
      report file written
  (e) capsys (non-tty): --json no -o → full JSON printed to stdout (unchanged contract)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline  # noqa: E402
from agentsweep.cli import main  # noqa: E402
from rich.console import Console  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# A single JSONL line containing both fake secrets
FIXTURE_LINE = (
    '{"type":"user","message":{"content":[{"type":"text",'
    f'"text":"key={AWS_KEY} and token {GH_TOKEN}"}}]}}}}\n'
)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Keep every test away from the real home (audit log at ~/.agentsweep/ lives there)."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def _mkroot(tmp_path: Path, n_files: int = 1, content: str = FIXTURE_LINE) -> Path:
    """Create a scan root with `n_files` JSONL files each containing `content`."""
    root = tmp_path / "history"
    root.mkdir(exist_ok=True)
    for i in range(n_files):
        (root / f"session_{i}.jsonl").write_text(content, encoding="utf-8")
    return root


def _many_findings_root(tmp_path: Path, n: int) -> Path:
    """Create a root with n separate files each containing one AWS key finding."""
    root = tmp_path / "history_many"
    root.mkdir(exist_ok=True)
    line = (
        '{"type":"user","message":{"content":[{"type":"text",'
        f'"text":"key={AWS_KEY}"}}]}}}}\n'
    )
    for i in range(n):
        (root / f"session_{i}.jsonl").write_text(line, encoding="utf-8")
    return root


# ------------------------------------------------------------------ (a)


def test_root_file_is_rejected_without_false_clean(tmp_path, capsys):
    """A file passed as --root must fail instead of reporting a clean scan."""
    root_file = tmp_path / "history.jsonl"
    root_file.write_text(FIXTURE_LINE, encoding="utf-8")

    code = main(["scan", "--root", str(root_file), "--json"])
    captured = capsys.readouterr()

    assert code == 2
    assert "must be a directory" in captured.err
    assert json.loads(captured.out) == []


def test_json_output_to_file_writes_valid_json(tmp_path, capsys):
    """scan --json -o FILE → valid JSON written to FILE with fingerprint/rule/masked."""
    root = _mkroot(tmp_path)
    out_file = tmp_path / "findings.json"

    code = main(["scan", "--root", str(root), "--json", "-o", str(out_file)])
    captured = capsys.readouterr()

    assert code == 1
    # stdout must be clean (no JSON dumped there)
    assert captured.out.strip() == ""
    # stderr must have a summary mentioning the file
    assert str(out_file) in captured.err or out_file.name in captured.err
    # the file must exist and be valid JSON
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert len(payload) >= 1
    for item in payload:
        assert "fingerprint" in item
        assert "rule" in item
        assert "masked" in item
    # secrets must be masked in the JSON, not raw
    raw_text = out_file.read_text(encoding="utf-8")
    assert AWS_KEY not in raw_text
    assert GH_TOKEN not in raw_text


def test_json_output_to_file_stderr_summary(tmp_path, capsys):
    """scan --json -o FILE → stderr contains finding count summary."""
    root = _mkroot(tmp_path)
    out_file = tmp_path / "findings.json"

    main(["scan", "--root", str(root), "--json", "-o", str(out_file)])
    captured = capsys.readouterr()

    # The summary must include a count of findings
    assert "finding" in captured.err.lower()


def test_json_output_legacy_flag_form(tmp_path, capsys):
    """Legacy --root X --json -o FILE form also works (no verb prefix)."""
    root = _mkroot(tmp_path)
    out_file = tmp_path / "out.json"

    code = main(["--root", str(root), "--json", "-o", str(out_file)])
    capsys.readouterr()

    assert code == 1
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(payload) >= 1


# ------------------------------------------------------------------ (b)


def test_human_mode_output_flag_writes_json(tmp_path, capsys):
    """scan -o FILE (human/table mode) writes findings JSON to FILE."""
    root = _mkroot(tmp_path)
    out_file = tmp_path / "report.json"

    code = main(["scan", "--root", str(root), "-o", str(out_file)])
    capsys.readouterr()

    assert code == 1
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert len(payload) >= 1
    for item in payload:
        assert "fingerprint" in item
        assert "rule" in item


def test_human_mode_output_flag_also_shows_table(tmp_path, capsys):
    """scan -o FILE still renders the human findings table to stdout."""
    root = _mkroot(tmp_path)
    out_file = tmp_path / "report.json"

    main(["scan", "--root", str(root), "-o", str(out_file)])
    out = capsys.readouterr().out

    # The normal scan output should still appear on stdout
    assert "FINDINGS" in out


def test_human_mode_output_flag_mentions_file(tmp_path, capsys):
    """scan -o FILE (human mode) prints a note about the written file to stderr."""
    root = _mkroot(tmp_path)
    out_file = tmp_path / "report.json"

    main(["scan", "--root", str(root), "-o", str(out_file)])
    captured = capsys.readouterr()

    # warn_line() goes to err_console (stderr); check the note appears somewhere
    combined = captured.out + captured.err
    assert out_file.name in combined or str(out_file) in combined


# ------------------------------------------------------------------ (c)


def test_json_antiflood_writes_default_file_not_stdout(tmp_path, monkeypatch, capsys):
    """Anti-flood: >30 findings + isatty→True, no -o → writes agentsweep-findings.json,
    stdout is NOT the JSON dump, stderr has summary, exit 1."""
    # Need more than JSON_FLOOD_LIMIT (30) findings
    root = _many_findings_root(tmp_path, n=35)

    # Make stdout look like a real terminal
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    # Change cwd so the default output file goes to tmp_path
    monkeypatch.chdir(tmp_path)

    code = main(["scan", "--root", str(root), "--json"])
    captured = capsys.readouterr()

    assert code == 1
    # stdout must NOT be the full JSON payload (anti-flood triggered)
    # It might be empty or contain a redirect notice but not the full array
    try:
        parsed = json.loads(captured.out)
        # If it does parse, it should NOT be a large list (would mean flood wasn't blocked)
        # An empty string parses as nothing; full payload would be a list of 35 items
        assert len(parsed) < 35, (
            "Anti-flood should have prevented >30 findings from going to stdout"
        )
    except (json.JSONDecodeError, ValueError):
        # stdout is not JSON at all (could be empty or a notice) — that's fine
        pass

    # The default findings file must exist in cwd
    default_file = tmp_path / pipeline.DEFAULT_JSON_NAME
    assert default_file.exists(), (
        f"{pipeline.DEFAULT_JSON_NAME} should have been written to cwd when "
        f"stdout is a tty and >30 findings found"
    )

    # stderr must have a summary mentioning the filename
    assert (
        pipeline.DEFAULT_JSON_NAME in captured.err or "findings" in captured.err.lower()
    )

    # The written file should be valid JSON with 35 findings
    payload = json.loads(default_file.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert len(payload) == 35


def test_json_antiflood_not_triggered_when_non_tty(tmp_path, monkeypatch, capsys):
    """Anti-flood must NOT trigger when stdout is NOT a tty (CI/pipe) — capsys env."""
    root = _many_findings_root(tmp_path, n=35)

    # capsys gives us non-tty stdout (the default in test environment)
    # Ensure isatty returns False (it should under capsys but be explicit)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)

    code = main(["scan", "--root", str(root), "--json"])
    captured = capsys.readouterr()

    assert code == 1
    # Full JSON must be on stdout (no flood protection for pipes)
    payload = json.loads(captured.out)
    assert isinstance(payload, list)
    assert len(payload) == 35


# ------------------------------------------------------------------ (d)


def test_human_antiflood_caps_table_and_writes_report(tmp_path, monkeypatch, capsys):
    """Human anti-flood: >40 findings + console.is_terminal→True → table capped,
    report file written."""
    # Need more than MAX_TABLE_ROWS (40) findings — 45 files with 1 finding each
    root = _many_findings_root(tmp_path, n=45)
    monkeypatch.chdir(tmp_path)

    # is_terminal is a read-only property on rich.Console; patch it on the class.
    with patch.object(
        Console, "is_terminal", new_callable=lambda: property(lambda self: True)
    ):
        code = main(["scan", "--root", str(root)])
        captured = capsys.readouterr()

    assert code == 1

    # A report file should have been written in cwd
    report_file = tmp_path / pipeline.DEFAULT_REPORT_NAME
    assert report_file.exists(), (
        f"{pipeline.DEFAULT_REPORT_NAME} should be written when table is capped"
    )

    # The stderr output should mention capping / "more"
    combined = captured.out + captured.err
    assert "more" in combined.lower() or report_file.name in combined


def test_human_antiflood_not_triggered_below_limit(tmp_path, monkeypatch, capsys):
    """Human mode with ≤40 findings must NOT write a report file."""
    root = _many_findings_root(tmp_path, n=5)
    monkeypatch.chdir(tmp_path)

    # is_terminal is a read-only property; patch it on the class.
    with patch.object(
        Console, "is_terminal", new_callable=lambda: property(lambda self: True)
    ):
        code = main(["scan", "--root", str(root)])

    assert code == 1
    report_file = tmp_path / pipeline.DEFAULT_REPORT_NAME
    assert not report_file.exists(), (
        "No report file should be written when findings are below the cap"
    )


# ------------------------------------------------------------------ (e)


def test_json_no_output_flag_prints_to_stdout_when_non_tty(tmp_path, capsys):
    """Under capsys (non-tty), --json with no -o still prints full JSON to stdout."""
    root = _mkroot(tmp_path)

    code = main(["scan", "--root", str(root), "--json"])
    captured = capsys.readouterr()

    assert code == 1
    payload = json.loads(captured.out)
    assert isinstance(payload, list)
    assert len(payload) >= 1
    # No file should be created (no -o, not a tty, under 30 findings)
    default_file = Path.cwd() / pipeline.DEFAULT_JSON_NAME
    assert not default_file.exists()


def test_json_clean_history_no_output_file_written(tmp_path, capsys):
    """scan --json with clean history writes [] to stdout, no file created."""
    root = tmp_path / "clean"
    root.mkdir()
    (root / "s.jsonl").write_text('{"message":"no secrets here"}\n', encoding="utf-8")

    code = main(["scan", "--root", str(root), "--json"])
    captured = capsys.readouterr()

    assert code == 0
    assert json.loads(captured.out) == []


def test_json_output_file_fingerprint_format(tmp_path, capsys):
    """Each finding in -o output has fingerprint in 'relpath:line:rule' format."""
    root = _mkroot(tmp_path)
    out_file = tmp_path / "findings.json"

    main(["scan", "--root", str(root), "--json", "-o", str(out_file)])
    payload = json.loads(out_file.read_text(encoding="utf-8"))

    for item in payload:
        fp = item["fingerprint"]
        # fingerprint format: "<relpath>:<line>:<rule>"
        parts = fp.rsplit(":", 2)
        assert len(parts) == 3, (
            f"fingerprint should have 3 colon-separated parts: {fp!r}"
        )
        _relpath, line_str, rule = parts
        assert line_str.isdigit(), f"fingerprint line should be a digit: {fp!r}"
        assert rule == item["rule"], f"fingerprint rule should match item rule: {fp!r}"


# ------------------------------------------------------------------ edge cases
def test_group_findings_groups_same_masked_secret():
    found_by_file = {
        "a.json": [
            (
                10,
                None,
                None,
                type(
                    "F",
                    (),
                    {
                        "rule": "openai",
                        "display": "OpenAI",
                        "masked": "sk-****1234",
                    },
                )(),
            ),
            (
                15,
                None,
                None,
                type(
                    "F",
                    (),
                    {
                        "rule": "openai",
                        "display": "OpenAI",
                        "masked": "sk-****1234",
                    },
                )(),
            ),
        ],
        "b.json": [
            (
                20,
                None,
                None,
                type(
                    "F",
                    (),
                    {
                        "rule": "openai",
                        "display": "OpenAI",
                        "masked": "sk-****1234",
                    },
                )(),
            )
        ],
    }

    groups = pipeline._group_findings(found_by_file)

    assert len(groups) == 1

    group = groups["sk-****1234"]

    assert group["rule"] == "openai"
    assert len(group["locations"]) == 3


def test_blast_radius_payload_never_contains_plaintext_secret():
    raw_secret = "sk-live-super-secret-value"

    finding = type(
        "F",
        (),
        {
            "rule": "openai",
            "display": "OpenAI",
            "masked": "sk-****1234",
        },
    )()

    found_by_file = {
        "a.json": [
            (10, None, raw_secret, finding),
            (15, None, raw_secret, finding),
        ],
        "b.json": [
            (20, None, raw_secret, finding),
        ],
    }

    report = pipeline._blast_radius_payload(found_by_file)
    blob = json.dumps(report)

    assert raw_secret not in blob
    assert "sk-****1234" in blob
    assert report[0]["occurrences"] == 3


def test_output_file_parent_does_not_exist_does_not_crash(tmp_path, capsys):
    """If -o points to a non-existent parent dir, _write_text logs to stderr
    and the process does not crash (graceful degradation)."""
    root = _mkroot(tmp_path)
    out_file = tmp_path / "no_such_dir" / "findings.json"

    # Should not raise; may log to stderr
    code = main(["scan", "--root", str(root), "--json", "-o", str(out_file)])
    captured = capsys.readouterr()

    # Exit code should still reflect findings (1) or write-error (2 via _write_text)
    # but should not be a Python exception / unhandled crash.
    assert code in (1, 2)
    # No Python traceback on stderr
    assert "Traceback" not in captured.err


def test_scan_warns_on_unparseable_lines_human_mode(tmp_path, capsys):
    """A malformed JSONL line must surface a not-scanned warning (#196)."""
    root = tmp_path / "history"
    root.mkdir()
    (root / "good.jsonl").write_text(FIXTURE_LINE, encoding="utf-8")
    (root / "bad.jsonl").write_text(
        '{"broken line with pasted ' + GH_TOKEN + " no closing brace\n",
        encoding="utf-8",
    )

    code = main(["scan", "--root", str(root)])
    captured = capsys.readouterr()

    assert code == 1  # the good file still has findings
    combined = captured.out + captured.err
    assert "not scanned" in combined
    assert "bad.jsonl" in combined


def test_scan_json_warns_on_unparseable_lines_stderr_only(tmp_path, capsys):
    """Machine mode: the not-scanned warning goes to stderr; stdout stays a
    valid JSON array (machine-clean contract unchanged)."""
    root = tmp_path / "history"
    root.mkdir()
    (root / "bad.jsonl").write_text(
        '{"broken line with pasted ' + GH_TOKEN + " no closing brace\n",
        encoding="utf-8",
    )

    code = main(["scan", "--root", str(root), "--json"])
    captured = capsys.readouterr()

    assert code == 0  # nothing scannable found — but the skip must be visible
    payload = json.loads(captured.out)
    assert payload == []
    assert "not scanned" in captured.err
    assert "bad.jsonl" in captured.err


def test_no_ignore_flag_skips_ignore_file(tmp_path, capsys):
    """--no-ignore means .agentsweepignore is not loaded (no suppression)."""
    # Use a file with only the AWS key so a single ignore rule covers everything.
    # Build line via concatenation to avoid f-string brace escaping confusion.
    aws_only_line = (
        '{"type":"user","message":{"content":[{"type":"text",'
        '"text":"key=' + AWS_KEY + '"}]}}\n'
    )
    root = tmp_path / "history_ignore"
    root.mkdir()
    (root / "session.jsonl").write_text(aws_only_line, encoding="utf-8")
    # Add an ignore file that suppresses the aws-access-key rule
    (root / ".agentsweepignore").write_text("rule:aws-access-key\n", encoding="utf-8")

    # Without --no-ignore, the finding is suppressed → exit 0
    code_with_ignore = main(["scan", "--root", str(root)])
    assert code_with_ignore == 0

    # With --no-ignore, the finding surfaces → exit 1
    code_no_ignore = main(["scan", "--root", str(root), "--no-ignore"])
    assert code_no_ignore == 1


def test_scan_verb_json_output_exit_code(tmp_path, capsys):
    """'scan' verb with --json returns exit 1 for findings, 0 for clean."""
    dirty = _mkroot(tmp_path)
    assert main(["scan", "--root", str(dirty), "--json"]) == 1

    clean = tmp_path / "clean2"
    clean.mkdir()
    (clean / "s.jsonl").write_text('{"msg":"nothing"}\n', encoding="utf-8")
    assert main(["scan", "--root", str(clean), "--json"]) == 0


def test_report_implies_json_and_includes_blast_radius(tmp_path, capsys):
    """scan --report (no --json) still emits JSON with blast_radius."""
    root = tmp_path / "hist"
    root.mkdir()
    # Use a clean tree so exit code is 0; shape still includes blast_radius.
    (root / "s.jsonl").write_text('{"msg":"nothing secret here"}\n', encoding="utf-8")
    code = main(["scan", "--root", str(root), "--report"])
    assert code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, dict)
    assert "findings" in data
    assert "blast_radius" in data
    assert data["blast_radius"] == []


def test_report_with_findings_groups_masked(tmp_path, capsys):
    """blast_radius groups by masked value when --report is set."""
    # Two files, same AWS key → one blast-radius group with occurrences >= 2.
    root = tmp_path / "hist"
    root.mkdir()
    line = (
        '{"type":"user","message":{"content":[{"type":"text",'
        f'"text":"key={AWS_KEY}"}}]}}}}\n'
    )
    (root / "a.jsonl").write_text(line, encoding="utf-8")
    (root / "b.jsonl").write_text(line, encoding="utf-8")
    code = main(["scan", "--root", str(root), "--report"])
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert "blast_radius" in data
    blob = json.dumps(data)
    assert AWS_KEY not in blob
    assert data["blast_radius"], "expected at least one blast-radius group"
    assert data["blast_radius"][0]["occurrences"] >= 2


def test_report_rejects_sarif(tmp_path):
    root = tmp_path / "hist"
    root.mkdir()
    (root / "s.jsonl").write_text('{"msg":"x"}\n', encoding="utf-8")
    try:
        main(["scan", "--root", str(root), "--report", "--format", "sarif"])
        raised = False
    except SystemExit as e:
        raised = True
        assert e.code == 2
    assert raised, "expected argparse error exit 2"


def test_report_rejects_fix(tmp_path):
    root = tmp_path / "hist"
    root.mkdir()
    (root / "s.jsonl").write_text('{"msg":"x"}\n', encoding="utf-8")
    try:
        main(
            [
                "fix",
                "--root",
                str(root),
                "--report",
                "--force",
                "--allow-production",
                "--no-backup",
            ]
        )
        raised = False
    except SystemExit as e:
        raised = True
        assert e.code == 2
    assert raised
