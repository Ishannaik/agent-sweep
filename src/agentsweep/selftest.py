"""Positive-control scanner selftest using a temporary Claude JSONL history.

This module intentionally covers four stable detector identities, not every rule
or source adapter.  It uses the same Source discovery, JSONL parsing, scanner,
and ignore-filter path as a normal Claude Code scan while never reading or
writing a user's history.
"""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import ignore as ignore_mod
from .sources import ClaudeCodeSource


# Keep this corpus independent of the currently configured regex rule list.
# Values are assembled at runtime so source control never contains a contiguous
# credential-shaped fixture.
_CONTROL_FILE = "scanner-control.jsonl"
_CONTROL_PREFIX = "scanner control: "
EXPECTED_COUNTS: dict[str, int] = {
    "anthropic": 1,
    "github-pat": 1,
    "aws-access-key": 1,
    "bip39-mnemonic": 1,
}


@dataclass(frozen=True)
class _ExpectedControl:
    """One fixed control outcome, including pipeline-attached metadata."""

    rule: str
    value: str
    text: str
    span: tuple[int, int]
    line: int
    keypath: tuple[str | int, ...]
    path: Path


@dataclass(frozen=True)
class SelftestResult:
    """Secret-free result of :func:`run_selftest`.

    ``expected`` contains active entries from a fixed positive-control corpus;
    it is deliberately not generated from active scanner rules. ``detected``
    includes every rule identity returned through the normal scan/filter path.
    ``skipped`` reports fixed controls excluded by explicit rule selection.
    ``metadata_matches`` confirms the expected value, span, line, logical
    keypath, and corpus path for each covered rule. ``error_type`` is an
    exception class or the fixed ``ScanWarning`` signal, never an exception
    message, because messages can contain scanned text.
    """

    ok: bool
    expected: dict[str, int]
    detected: dict[str, int]
    suppressed: int
    metadata_matches: dict[str, bool] = field(default_factory=dict)
    skipped: tuple[str, ...] = ()
    error_type: str | None = None
    selection_error: str | None = None

    def as_dict(self) -> dict:
        """Serialize safe coverage statuses without exposing scanned control text."""

        rule_ids = tuple(EXPECTED_COUNTS)
        coverage = []
        for rule_id in rule_ids:
            expected = self.expected.get(rule_id, 0)
            detected = self.detected.get(rule_id, 0)
            if rule_id in self.skipped:
                status = "skipped-by-rule-filter"
            elif detected != expected:
                status = "count-mismatch"
            elif not self.metadata_matches.get(rule_id, False):
                status = "metadata-mismatch"
            else:
                status = "ok"
            coverage.append(
                {
                    "rule": rule_id,
                    "expected": expected,
                    "detected": detected,
                    "status": status,
                }
            )
        return {
            "ok": self.ok,
            "control": "claude-code-jsonl",
            "coverage": coverage,
            "suppressed": self.suppressed,
            "error_type": self.error_type,
            "selection_error": self.selection_error,
        }


def run_selftest(
    root: Path | None = None,
    *,
    no_ignore: bool = False,
    exclude_rules: set[str] | None = None,
    only_rules: set[str] | None = None,
) -> SelftestResult:
    """Scan a temporary canonical Claude JSONL corpus through the full path.

    ``root`` selects the same project-level ignore context that a scan of that
    source root would use; it is never scanned or written. The current working
    directory is also consulted unless ``no_ignore`` is true. Explicit rule
    selection narrows the four fixed controls, but selecting none is an error.
    Ignore suppression never narrows expectations. Any missing, duplicate,
    unexpected, or misidentified hit; metadata mismatch; scan warning; and
    every temporary-file, source, or scanner exception returns a failed result.
    The temporary corpus is removed before this function returns.
    """
    exclude_rules = exclude_rules or set()
    only_rules = only_rules or None
    active_rules, skipped = _active_control_rules(exclude_rules, only_rules)
    expected = {rule_id: 1 for rule_id in active_rules}
    if not expected:
        return SelftestResult(
            ok=False,
            expected=expected,
            detected={},
            suppressed=0,
            skipped=skipped,
            selection_error=(
                "No positive controls are selected by --only-rule/--exclude-rule."
            ),
        )

    try:
        effective_root = (root or Path.cwd()).resolve()
        ignores = (
            ignore_mod.IgnoreSet()
            if no_ignore
            else ignore_mod.load([effective_root, Path.cwd()])
        )
        with tempfile.TemporaryDirectory(prefix="agentsweep-selftest-") as tmp:
            canary_root = Path(tmp)
            corpus = canary_root / _CONTROL_FILE
            values = _control_values()
            corpus.write_text(_canonical_claude_jsonl(values), encoding="utf-8")
            source = ClaudeCodeSource(root=canary_root)

            # Import lazily: pipeline calls this module for --verify-scanner.
            # _scan_all is the shared discovery/parse/scanner/filter path.
            from .pipeline import _scan_all

            found_by_file, _, suppressed, truncated = _scan_all(
                source,
                list(source.iter_files()),
                ignores,
                exclude_rules=exclude_rules,
                only_rules=only_rules,
            )
            detected = Counter(
                finding.rule
                for items in found_by_file.values()
                for _, _, _, finding in items
            )
            metadata_matches = _metadata_matches(
                found_by_file, _expected_controls(corpus, values, active_rules)
            )
            scan_warned = bool(
                truncated
                or getattr(source, "unscannable_lines", None)
                or getattr(source, "unreadable_files", None)
            )
    except Exception as exc:
        return SelftestResult(
            ok=False,
            expected=expected,
            detected={},
            suppressed=0,
            skipped=skipped,
            error_type=type(exc).__name__,
        )

    detected_dict = dict(sorted(detected.items()))
    return SelftestResult(
        ok=(
            not scan_warned
            and detected_dict == expected
            and all(metadata_matches.values())
        ),
        expected=expected,
        detected=detected_dict,
        suppressed=suppressed,
        metadata_matches=metadata_matches,
        skipped=skipped,
        error_type="ScanWarning" if scan_warned else None,
    )


def _control_values() -> dict[str, str]:
    """Build the fixed low-entropy controls without consulting scanner rules."""
    return {
        "anthropic": "sk-ant-api-" + "a" * 32,
        "github-pat": "ghp_" + "a" * 36,
        "aws-access-key": "AKIA" + "A" * 16,
        "bip39-mnemonic": " ".join(["abandon"] * 11 + ["about"]),
    }


def _control_texts(values: dict[str, str]) -> dict[str, str]:
    """Return fixed logical values stored in the canonical Claude record."""
    return {
        "anthropic": _CONTROL_PREFIX + values["anthropic"],
        "github-pat": _CONTROL_PREFIX + values["github-pat"],
        "aws-access-key": _CONTROL_PREFIX + values["aws-access-key"],
        "bip39-mnemonic": values["bip39-mnemonic"],
    }


def _canonical_claude_jsonl(values: dict[str, str]) -> str:
    """Build one canonical Claude Code JSONL record with four controls."""
    texts = _control_texts(values)
    content = [{"type": "text", "text": texts[rule_id]} for rule_id in EXPECTED_COUNTS]
    return json.dumps({"type": "user", "message": {"content": content}}) + "\n"


def _active_control_rules(
    exclude_rules: set[str] | None,
    only_rules: set[str] | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return fixed controls active under the pipeline's effective rule filters."""
    excluded = exclude_rules or set()
    only = only_rules or None
    active = tuple(
        rule_id
        for rule_id in EXPECTED_COUNTS
        if rule_id not in excluded and (only is None or rule_id in only)
    )
    skipped = tuple(rule_id for rule_id in EXPECTED_COUNTS if rule_id not in active)
    return active, skipped


def _expected_controls(
    corpus: Path,
    values: dict[str, str],
    active_rules: tuple[str, ...],
) -> tuple[_ExpectedControl, ...]:
    """Return fixed expected hits independent of active scanner rule internals."""
    texts = _control_texts(values)
    controls = []
    for index, rule_id in enumerate(EXPECTED_COUNTS):
        if rule_id not in active_rules:
            continue
        value = values[rule_id]
        text = texts[rule_id]
        start = 0 if rule_id == "bip39-mnemonic" else len(_CONTROL_PREFIX)
        controls.append(
            _ExpectedControl(
                rule=rule_id,
                value=value,
                text=text,
                span=(start, start + len(value)),
                line=1,
                keypath=("message", "content", index, "text"),
                path=corpus,
            )
        )
    return tuple(controls)


def _metadata_matches(
    found_by_file: dict,
    expected_controls: tuple[_ExpectedControl, ...],
) -> dict[str, bool]:
    """Match pipeline findings to the complete fixed control metadata."""
    expected_by_rule = {control.rule: control for control in expected_controls}
    matches = {rule_id: False for rule_id in expected_by_rule}
    for path, items in found_by_file.items():
        for line, keypath, text, finding in items:
            control = expected_by_rule.get(finding.rule)
            if control is None:
                continue
            if (
                path == control.path
                and line == control.line
                and tuple(keypath) == control.keypath
                and text == control.text
                and finding.file == control.path
                and finding.line == control.line
                and tuple(finding.keypath) == control.keypath
                and finding.value == control.value
                and finding.span == control.span
            ):
                matches[control.rule] = True
    return matches
