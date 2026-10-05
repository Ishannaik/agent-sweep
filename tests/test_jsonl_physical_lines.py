"""JSONL records are physical lines: the reader and the writer must agree.

`JsonlSource.iter_strings` numbers records by splitting the file's *bytes*, where
a record ends at ``\\r\\n``, ``\\r`` or ``\\n``. `JsonlSource.apply_redactions` used
to re-split the decoded *text* with ``str.splitlines(keepends=True)``, which also
breaks on U+0085 (NEL), U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR)
-- code points RFC 8259 allows to appear raw inside a JSON string, and which
``json.dumps(..., ensure_ascii=False)`` writes through unescaped. The two models
therefore disagree about which line a record lives on, so a ``(line_number,
keypath)`` pair produced by the scan is applied to a different record than the one
it names, and ``redactor._validate_jsonl`` sees an "invalid" first line and refuses
to redact such a file at all.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline  # noqa: E402
from agentsweep.cli import main  # noqa: E402
from agentsweep.redactor import SafetyError, safe_write  # noqa: E402
from agentsweep.sources import ClaudeCodeSource  # noqa: E402

# AWS's documented example key, not a live credential -- the same value the
# existing suite already uses, e.g. tests/test_line_endings.py:24.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
MARKER = "[REDACTED:aws-access-key]"

_RECORD_PLAIN = '{"role":"assistant","text":"hello there"}'
_RECORD_WITH_SECRET = '{"role":"user","text":"key=%s"}' % AWS_KEY

NEL = chr(0x85)
LINE_SEPARATOR = chr(0x2028)
PARAGRAPH_SEPARATOR = chr(0x2029)

WIDE_BREAKS = {
    "LINE_SEPARATOR": LINE_SEPARATOR,
    "NEL": NEL,
    "PARAGRAPH_SEPARATOR": PARAGRAPH_SEPARATOR,
}


def _record_with(separator: str) -> str:
    """A JSONL record whose string value holds a raw line-breaking code point."""
    return '{"role":"user","text":"before' + separator + 'after"}'


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Keep the audit log (~/.agentsweep/audit.jsonl) inside tmp_path."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture(autouse=True)
def _no_running_agent(monkeypatch):
    monkeypatch.setattr(pipeline, "is_agent_running", lambda markers: (False, ""))


def _records(content: str) -> list[dict]:
    """Parse the file the way JSONL defines it: one record per physical line."""
    return [json.loads(line) for line in content.split("\n") if line.strip()]


def _session(tmp_path: Path, separator: str = LINE_SEPARATOR) -> Path:
    root = tmp_path / "projects"
    root.mkdir()
    session = root / "session.jsonl"
    session.write_text(
        "\n".join([_record_with(separator), _RECORD_PLAIN, _RECORD_WITH_SECRET]) + "\n",
        encoding="utf-8",
    )
    return session


def test_scan_line_numbers_address_the_record_they_name(tmp_path):
    session = _session(tmp_path)
    source = ClaudeCodeSource(root=tmp_path / "projects")

    planted = [
        (ln, kp) for ln, kp, value in source.iter_strings(session) if AWS_KEY in value
    ]
    assert len(planted) == 1, "the planted secret must be found exactly once"
    line_num, key_path = planted[0]

    new_content = source.apply_redactions(session, [(line_num, key_path, MARKER)])

    records = _records(new_content)
    assert len(records) == 3, "one record per physical line, wide breaks included"
    assert records[2]["text"] == MARKER, (
        "the record the scan named must be the one rewritten"
    )
    assert AWS_KEY not in new_content, "the secret must actually leave the file"


def test_redaction_leaves_the_other_records_verbatim(tmp_path):
    session = _session(tmp_path)
    source = ClaudeCodeSource(root=tmp_path / "projects")

    entries = list(source.iter_strings(session))
    secret_line = next(ln for ln, _kp, value in entries if AWS_KEY in value)
    plain_line = next(ln for ln, _kp, value in entries if value == "hello there")
    assert secret_line != plain_line, (
        "fixture sanity: the two live in different records"
    )

    new_content = source.apply_redactions(session, [(secret_line, ["text"], MARKER)])

    records = _records(new_content)
    assert records[plain_line - 1]["text"] == "hello there", (
        "an innocent record must not be rewritten"
    )
    assert records[0]["text"] == f"before{LINE_SEPARATOR}after"


@pytest.mark.parametrize("label", sorted(WIDE_BREAKS))
def test_redact_completes_on_a_file_containing_a_wide_break(tmp_path, label):
    session = _session(tmp_path, WIDE_BREAKS[label])

    code = main(
        [
            "--source",
            "claude-code",
            "--root",
            str(tmp_path / "projects"),
            "--fix",
            "--force",
        ]
    )

    assert code == 0, label
    redacted = session.read_text(encoding="utf-8")
    assert AWS_KEY not in redacted, label
    assert MARKER in redacted, label
    assert len(_records(redacted)) == 3, label
    assert _records(redacted)[0]["text"] == f"before{WIDE_BREAKS[label]}after", label


def test_untouched_file_is_not_rewritten(tmp_path):
    root = tmp_path / "projects"
    root.mkdir()
    session = root / "quiet.jsonl"
    original = _record_with(LINE_SEPARATOR) + "\n" + _RECORD_PLAIN + "\n"
    session.write_text(original, encoding="utf-8")

    assert (
        main(["--source", "claude-code", "--root", str(root), "--fix", "--force"]) == 0
    )

    assert session.read_text(encoding="utf-8") == original
    assert not session.with_name("quiet.jsonl.bak").exists()


@pytest.mark.parametrize(
    "text",
    [
        "",
        "a",
        "a\n",
        "a\r\n",
        "a\n\nb",
        "a\r\rb",
        "a\r\nb\r",
        "a" + NEL + "b",
        "a" + LINE_SEPARATOR + "b",
        "a" + PARAGRAPH_SEPARATOR + "b",
        LINE_SEPARATOR,
        "\n",
        "a\n" + LINE_SEPARATOR,
        # str.splitlines() also breaks on these, but JSON requires control
        # characters to be escaped, so a valid record can never hold one raw:
        # they must not become record boundaries either.
        "a" + chr(0x0B) + "b",
        "a" + chr(0x0C) + "b",
        "a" + chr(0x1C) + "b",
    ],
)
def test_record_split_matches_the_terminators_the_reader_uses(text):
    """jsonl_lines() must agree with the bytes.splitlines() the scan numbers with."""
    from agentsweep.redactor import jsonl_lines

    assert [line.rstrip("\r\n") for line in jsonl_lines(text)] == [
        chunk.decode("utf-8") for chunk in text.encode("utf-8").splitlines()
    ]
    assert "".join(jsonl_lines(text)) == text, "no character may be lost or duplicated"


def test_undo_restores_a_file_containing_a_wide_break(tmp_path):
    session = _session(tmp_path)
    original = session.read_bytes()

    assert (
        main(
            [
                "--source",
                "claude-code",
                "--root",
                str(tmp_path / "projects"),
                "--fix",
                "--force",
            ]
        )
        == 0
    )
    backup = session.with_name("session.jsonl.bak")
    assert backup.read_bytes() == original

    assert (
        main(["undo", "--source", "claude-code", "--root", str(tmp_path / "projects")])
        == 0
    )
    assert session.read_bytes() == original
    assert not backup.exists()


def test_shared_helpers_scan_every_record(tmp_path):
    """The _helpers pair behind the _vscode / _extended / _community / _more adapters."""
    from agentsweep.sources._helpers import _apply_jsonl_redactions, _iter_jsonl_strings

    session = tmp_path / "s.jsonl"
    session.write_text(
        '{"role":"user","text":"pasted'
        + LINE_SEPARATOR
        + "key="
        + AWS_KEY
        + '"}\n'
        + _RECORD_PLAIN
        + "\n",
        encoding="utf-8",
    )

    entries = list(_iter_jsonl_strings(session))

    assert [ln for ln, _kp, value in entries if AWS_KEY in value] == [1], (
        "the record holding the key must be scanned, and numbered as record 1"
    )
    assert [ln for ln, _kp, _v in entries] == [1, 1, 2, 2], (
        "one line number per physical record"
    )

    redacted = _apply_jsonl_redactions(session, [(1, ["text"], MARKER)])

    records = _records(redacted)
    assert records[0]["text"] == MARKER
    assert records[1]["text"] == "hello there"
    assert AWS_KEY not in redacted


def test_json_loads_rejects_the_other_wide_breaks():
    """Why U+0085/U+2028/U+2029 are the whole set rather than an arbitrary pick.

    ``str.splitlines()`` additionally breaks on U+000B, U+000C and U+001C-U+001E,
    but those are control characters that JSON requires to be escaped, so a valid
    record can never contain one raw -- while the three above are accepted.
    """
    for control in (chr(0x0B), chr(0x0C), chr(0x1C)):
        with pytest.raises(json.JSONDecodeError):
            json.loads('{"t": "a' + control + 'b"}')
    for wide in (NEL, LINE_SEPARATOR, PARAGRAPH_SEPARATOR):
        assert json.loads('{"t": "a' + wide + 'b"}')["t"] == "a" + wide + "b"


def test_line_count_guard_still_refuses_an_added_line_break(tmp_path):
    """The preserved invariant: a write that gains a wide break is still refused.

    ``_validate_jsonl`` now iterates records, so on its own it accepts this
    content; ``safe_write``'s line-count check (left on ``str.splitlines``) is what
    catches a redaction that introduces an extra break.
    """
    session = tmp_path / "session.jsonl"
    session.write_text('{"role":"user","text":"plain"}\n', encoding="utf-8")

    with pytest.raises(SafetyError, match="Line count changed after redaction"):
        safe_write(
            session, '{"role":"user","text":"a' + LINE_SEPARATOR + 'b"}\n', fmt="jsonl"
        )


@pytest.mark.parametrize(
    "content, keypath",
    [
        # terminator of the rewritten record is in the middle of the file
        (
            '{"role":"user","text":"key=%s"}\r{"role":"assistant","text":"hi"}\r'
            % AWS_KEY,
            ["text"],
        ),
        # and at the very end of the file
        (
            '{"role":"user","text":"hi"}\r{"role":"user","text":"key=%s"}\r' % AWS_KEY,
            ["text"],
        ),
    ],
)
def test_redaction_preserves_a_lone_cr_record_terminator(tmp_path, content, keypath):
    """A rewritten record must keep whatever terminator ended it, including bare CR."""
    root = tmp_path / "projects"
    root.mkdir()
    session = root / "cr.jsonl"
    session.write_text(content, encoding="utf-8")
    source = ClaudeCodeSource(root=root)

    line, path = next(
        (ln, kp) for ln, kp, value in source.iter_strings(session) if AWS_KEY in value
    )
    new_content = source.apply_redactions(session, [(line, path, MARKER)])

    assert new_content.count("\r") == content.count("\r"), (
        "the CR terminators must survive"
    )
    assert new_content.endswith("\r"), (
        "the final lone CR terminator must not be dropped"
    )
    assert AWS_KEY not in new_content
    assert len(_records(new_content.replace("\r", "\n"))) == 2, (
        "no two records may be merged"
    )


def test_plaintext_redaction_preserves_a_lone_cr_line_terminator(tmp_path):
    """``_line_ending`` is shared, so the text path keeps a bare CR too."""
    from agentsweep.sources._helpers import _apply_plaintext_redactions

    path = tmp_path / "memory.md"
    content = "note one\r" + "key=" + AWS_KEY + "\r"
    path.write_bytes(content.encode("utf-8"))

    new_content = _apply_plaintext_redactions(path, [(2, [], MARKER)])

    assert new_content == "note one\r" + MARKER + "\r"
    assert new_content.endswith("\r"), (
        "the final lone CR terminator must not be dropped"
    )
