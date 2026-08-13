"""Property tests for the generic SQLite redaction round-trip.

Warp, Crush, Grok CLI, Kiro CLI, and Zed all share
``_GenericSqliteSource``.  The generated database below combines a Warp-like
plain-text column with Crush-like JSON stored in a text column, so the same
public ``fix``/``undo`` path exercises both update branches.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from string import ascii_uppercase
from tempfile import TemporaryDirectory
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import main  # noqa: E402

SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented synthetic example key ID.
MARKER = "[REDACTED:aws-access-key]"

_TEXT = st.text(
    # Excluding ASCII uppercase makes the planted AWS IDs the only values that
    # can match the aws-access-key rule, so marker-count equality is exact.
    alphabet=st.characters(
        blacklist_categories=("Cs",), blacklist_characters=ascii_uppercase
    ),
    max_size=64,
).filter(lambda value: SECRET not in value and "[REDACTED:" not in value)


@st.composite
def _secret_bearing_text(draw) -> str:
    """Mix boundary placement, repeated matches, CRLF, and arbitrary Unicode."""
    before = draw(_TEXT)
    after = draw(_TEXT)
    separator = draw(st.sampled_from((" ", "\r\n", " — ", " 🧪 ")))
    count = draw(st.integers(min_value=1, max_value=3))
    planted = separator.join([SECRET] * count)
    placement = draw(st.sampled_from(("start", "middle", "end")))
    if placement == "start":
        return planted + (separator + after if after else "")
    if placement == "end":
        return (before + separator if before else "") + planted
    return (
        (before + separator if before else "")
        + planted
        + (separator + after if after else "")
    )


@dataclass(frozen=True)
class _Payload:
    plain: str
    nested: str


@st.composite
def _payloads(draw) -> _Payload:
    return _Payload(
        plain=draw(_secret_bearing_text()),
        nested=draw(_secret_bearing_text()),
    )


@dataclass(frozen=True)
class _RoundTrip:
    original: bytes
    redacted: bytes
    second_fix: bytes
    restored: bytes
    text_values: tuple[str, ...]
    nested_json: object
    integrity: str
    expected_markers: int


def _make_generic_db(root: Path, payload: _Payload) -> Path:
    root.mkdir(parents=True)
    db = root / "warp.sqlite"
    con = sqlite3.connect(db)
    try:
        con.execute(
            "CREATE TABLE agent_conversations "
            "(id INTEGER PRIMARY KEY, role TEXT, content TEXT)"
        )
        con.execute(
            "INSERT INTO agent_conversations (role, content) VALUES (?, ?)",
            ("user", payload.plain),
        )
        con.execute(
            "CREATE TABLE messages "
            "(id INTEGER PRIMARY KEY, parts TEXT, token_count INTEGER, raw BLOB)"
        )
        con.execute(
            "INSERT INTO messages (parts, token_count, raw) VALUES (?, ?, ?)",
            (
                json.dumps(
                    {
                        "messages": [
                            {"parts": [{"type": "text", "text": payload.nested}]}
                        ]
                    },
                    ensure_ascii=False,
                ),
                7,
                b"not a text column",
            ),
        )
        con.commit()
    finally:
        con.close()
    return db


def _quiet_main(args: list[str]) -> int:
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        return main(args)


def _exercise(payload: _Payload, test_root: Path) -> _RoundTrip:
    with TemporaryDirectory(dir=test_root) as tmp:
        home = Path(tmp)
        root = home / "warp"
        db = _make_generic_db(root, payload)
        original = db.read_bytes()
        environment = {"HOME": str(home), "USERPROFILE": str(home)}
        fix_args = [
            "fix",
            "--source",
            "warp",
            "--root",
            str(root),
            "--force",
            "--allow-production",
        ]

        with (
            patch.dict(os.environ, environment),
            patch("agentsweep.pipeline.is_agent_running", return_value=(False, "")),
        ):
            assert _quiet_main(fix_args) == 0
            redacted = db.read_bytes()

            con = sqlite3.connect(db)
            try:
                integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
                plain = con.execute(
                    "SELECT content FROM agent_conversations"
                ).fetchone()[0]
                parts = con.execute("SELECT parts FROM messages").fetchone()[0]
            finally:
                con.close()
            text_values = (plain, parts)
            nested_json = json.loads(parts)

            assert _quiet_main(fix_args) == 0
            second_fix = db.read_bytes()

            undo_args = ["undo", "--source", "warp", "--root", str(root)]
            assert _quiet_main(undo_args) == 0
            restored = db.read_bytes()

    return _RoundTrip(
        original=original,
        redacted=redacted,
        second_fix=second_fix,
        restored=restored,
        text_values=text_values,
        nested_json=nested_json,
        integrity=integrity,
        expected_markers=payload.plain.count(SECRET) + payload.nested.count(SECRET),
    )


_PROPERTY_SETTINGS = settings(
    max_examples=25,
    derandomize=True,
    deadline=None,
    # tmp_path is only the parent of a fresh TemporaryDirectory per example,
    # so no generated case can observe another case's database or backup.
    suppress_health_check=(HealthCheck.function_scoped_fixture,),
)


@_PROPERTY_SETTINGS
@given(payload=_payloads())
def test_fix_then_undo_restores_original_bytes(
    payload: _Payload, tmp_path: Path
) -> None:
    result = _exercise(payload, tmp_path)
    assert result.redacted != result.original
    assert result.restored == result.original


@_PROPERTY_SETTINGS
@given(payload=_payloads())
def test_fix_preserves_sqlite_integrity(payload: _Payload, tmp_path: Path) -> None:
    assert _exercise(payload, tmp_path).integrity == "ok"


@_PROPERTY_SETTINGS
@given(payload=_payloads())
def test_fix_removes_plaintext_from_every_text_column(
    payload: _Payload, tmp_path: Path
) -> None:
    result = _exercise(payload, tmp_path)
    assert SECRET.encode() not in result.redacted
    assert all(SECRET not in value for value in result.text_values)
    assert sum(value.count(MARKER) for value in result.text_values) == (
        result.expected_markers
    )


@_PROPERTY_SETTINGS
@given(payload=_payloads())
def test_fix_keeps_nested_text_as_valid_json(payload: _Payload, tmp_path: Path) -> None:
    nested = _exercise(payload, tmp_path).nested_json
    assert isinstance(nested, dict)
    assert nested["messages"][0]["parts"][0]["type"] == "text"
    assert MARKER in nested["messages"][0]["parts"][0]["text"]


@_PROPERTY_SETTINGS
@given(payload=_payloads())
def test_second_fix_is_byte_for_byte_idempotent(
    payload: _Payload, tmp_path: Path
) -> None:
    result = _exercise(payload, tmp_path)
    assert result.second_fix == result.redacted
