"""SARIF 2.1.0 output: structure, masking, exit codes, and CLI contract.

Structural assertions plus spec-compliance validation against a vendored
copy of the OASIS SARIF 2.1.0 JSON schema (tests/fixtures/sarif/) — no
network, per the project's hermetic-test rule.
"""

from __future__ import annotations

import json
import os
import sys
import time
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

import jsonschema
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.cli import main  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

_LINE = (
    '{{"type":"user","message":{{"role":"user","content":'
    '[{{"type":"text","text":"{secret}"}}]}}}}\n'
)


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def _seed(base: Path, *secrets: str) -> Path:
    root = base / "scan_root"
    root.mkdir(parents=True, exist_ok=True)
    f = root / "session.jsonl"
    f.write_text(
        "".join(_LINE.format(secret=f"key={s}") for s in secrets),
        encoding="utf-8",
    )
    past = time.time() - 3700
    os.utime(f, (past, past))
    return root


def _scan_sarif(root: Path, capsys) -> dict:
    code = main(["scan", "--root", str(root), "--format", "sarif"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    doc["_exit"] = code
    return doc


# The OASIS SARIF 2.1.0 JSON schema is vendored under tests/fixtures/sarif/.
# Loaded once per session (110 KB, ~5 ms to parse) and cached so 3+ validation
# tests don't re-read+re-parse the file. The schema lives in the same repo
# checkout, so this stays hermetic — no network call.
_SARIF_SCHEMA_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
)


@lru_cache(maxsize=1)
def _sarif_schema() -> dict:
    return json.loads(_SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))


def _assert_valid_sarif(doc: dict) -> None:
    """Raise ValidationError if `doc` is not a spec-compliant SARIF 2.1.0 doc.

    Catches the bug class of "spec compliance drift": a future change to
    `_sarif_document()` could emit structurally-plausible output that fails
    GitHub Code Scanning / VS Code SARIF Viewer ingestion, and the existing
    field-by-field tests would not catch it. Validating against the OASIS
    schema is the canonical answer — see issue #132.
    """
    # `validate()` raises ValidationError (subclass of ValueError) on failure;
    # it returns None on success, so the assertion is implicit.
    jsonschema.validate(instance=doc, schema=_sarif_schema())


def test_sarif_shape(tmp_path, capsys):
    doc = _scan_sarif(_seed(tmp_path, AWS_KEY), capsys)

    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agentsweep"
    assert driver["informationUri"]
    assert driver["version"]


def test_rules_carry_rotation_guidance(tmp_path, capsys):
    doc = _scan_sarif(_seed(tmp_path, AWS_KEY), capsys)

    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    aws = next(r for r in rules if r["id"] == "aws-access-key")
    assert aws["name"] == "AWS access key"
    assert "aws iam create-access-key" in aws["help"]["text"]


def test_only_matched_rules_are_emitted(tmp_path, capsys):
    doc = _scan_sarif(_seed(tmp_path, AWS_KEY), capsys)

    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["aws-access-key"]


def test_result_location_points_at_the_file(tmp_path, capsys):
    root = _seed(tmp_path, AWS_KEY)
    doc = _scan_sarif(root, capsys)

    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "aws-access-key"
    assert result["level"] == "error"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] == 1
    uri = loc["artifactLocation"]["uri"]
    assert uri.startswith("file://")
    resolved = Path(url2pathname(urlparse(uri).path))
    assert resolved.name == "session.jsonl"


def test_rule_index_resolves_into_rules(tmp_path, capsys):
    doc = _scan_sarif(_seed(tmp_path, AWS_KEY, GH_TOKEN), capsys)

    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_secret_plaintext_never_appears(tmp_path, capsys):
    doc = _scan_sarif(_seed(tmp_path, AWS_KEY, GH_TOKEN), capsys)
    doc.pop("_exit")

    blob = json.dumps(doc)
    assert AWS_KEY not in blob
    assert GH_TOKEN not in blob
    assert "AKIAIO" in blob  # the masked preview is still there



def test_exit_code_matches_json_path(tmp_path, capsys):
    assert _scan_sarif(_seed(tmp_path, AWS_KEY), capsys)["_exit"] == 1


def test_clean_root_is_valid_empty_sarif(tmp_path, capsys):
    root = tmp_path / "clean"
    root.mkdir()
    f = root / "session.jsonl"
    f.write_text('{"type":"user","message":"nothing here"}\n', encoding="utf-8")
    past = time.time() - 3700
    os.utime(f, (past, past))

    doc = _scan_sarif(root, capsys)
    assert doc["_exit"] == 0
    assert doc["runs"][0]["results"] == []


def test_missing_root_still_emits_valid_sarif(tmp_path, capsys):
    code = main(["scan", "--root", str(tmp_path / "nope"), "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)

    assert code == 2
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_output_file_keeps_stdout_clean(tmp_path, capsys):
    root = _seed(tmp_path, AWS_KEY)
    dest = tmp_path / "out.sarif"

    code = main(["scan", "--root", str(root), "--format", "sarif", "-o", str(dest)])
    captured = capsys.readouterr()

    assert code == 1
    assert captured.out == ""
    doc = json.loads(dest.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert AWS_KEY not in dest.read_text(encoding="utf-8")


def test_sarif_rejects_json_combination(tmp_path):
    with pytest.raises(SystemExit):
        main(["scan", "--root", str(tmp_path), "--format", "sarif", "--json"])


def test_sarif_rejected_on_fix(tmp_path):
    with pytest.raises(SystemExit):
        main(["fix", "--root", str(tmp_path), "--format", "sarif"])


def test_sarif_validates_against_vendored_schema(tmp_path, capsys):
    """Regression for #132: a multi-rule scan's SARIF output must validate
    against the OASIS SARIF 2.1.0 JSON schema, not just the field-by-field
    structural assertions above."""
    doc = _scan_sarif(_seed(tmp_path, AWS_KEY, GH_TOKEN), capsys)
    doc.pop("_exit", None)  # internal-only key, not part of the SARIF spec
    _assert_valid_sarif(doc)


def test_empty_sarif_validates_against_vendored_schema(tmp_path, capsys):
    """Edge case: a clean root's SARIF output (empty results array) must
    still validate against the schema — guards against an empty-results
    drift in `_sarif_document()`."""
    root = tmp_path / "clean"
    root.mkdir()
    f = root / "session.jsonl"
    f.write_text('{"type":"user","message":"nothing here"}\n', encoding="utf-8")
    past = time.time() - 3700
    os.utime(f, (past, past))

    doc = _scan_sarif(root, capsys)
    doc.pop("_exit", None)
    _assert_valid_sarif(doc)


def test_missing_root_sarif_validates_against_vendored_schema(tmp_path, capsys):
    """Edge case: the error-path SARIF (missing root, exit code 2) must
    still validate against the schema — same bug class, different code path
    through `_sarif_document([])`."""
    code = main(["scan", "--root", str(tmp_path / "nope"), "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)

    assert code == 2
    _assert_valid_sarif(doc)
