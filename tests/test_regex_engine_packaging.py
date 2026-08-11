"""Packaging contracts for the optional RE2 acceleration extra."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os

import pytest

from _regex_engine_support import run_text_scan


RE2_AUTO = (
    importlib.util.find_spec("re2") is not None
    and os.environ.get("AGENTSWEEP_REGEX_ENGINE", "auto").lower() == "auto"
)


def test_fast_extra_is_present_in_installed_metadata() -> None:
    metadata = importlib.metadata.metadata("agentsweep")
    requirements = metadata.get_all("Requires-Dist") or []

    assert "fast" in (metadata.get_all("Provides-Extra") or [])
    assert any("google-re2" in requirement and "extra == 'fast'" in requirement for requirement in requirements)


def test_default_auto_mode_handles_a_missing_optional_import() -> None:
    result = run_text_scan(["ordinary text"], mode="auto", block_re2=True)

    assert result["summary"]["re2_available"] is False
    assert result["summary"]["re2_rule_count"] == 0


@pytest.mark.skipif(
    importlib.util.find_spec("re2") is None,
    reason="requires optional google-re2 extra",
)
def test_fast_extra_activates_real_re2_rules() -> None:
    result = run_text_scan(["ordinary text"], mode="auto")

    assert result["summary"]["re2_available"] is True
    assert result["summary"]["re2_rule_count"] > 0


@pytest.mark.skipif(not RE2_AUTO, reason="requires auto mode with google-re2")
def test_long_ascii_text_dispatches_a_selected_rule_to_re2() -> None:
    from agentsweep.regex_engine import RE2_MIN_INPUT_CHARS
    from agentsweep.scanner import ENGINE_RULES, scan_text

    rule = next(
        pattern for rule_id, _display, pattern in ENGINE_RULES
        if rule_id == "aws-access-key"
    )
    original = rule._compiled
    calls: list[object] = []

    class TrackingPattern:
        def finditer(self, source):
            calls.append(source)
            return original.finditer(source)

    object.__setattr__(rule, "_compiled", TrackingPattern())
    try:
        assert scan_text("x" * RE2_MIN_INPUT_CHARS + " AKIAIOSFODNN7EXAMPLE")
    finally:
        object.__setattr__(rule, "_compiled", original)

    assert calls and isinstance(calls[0], bytes)


@pytest.mark.skipif(not RE2_AUTO, reason="requires auto mode with google-re2")
def test_dense_re2_rule_restarts_with_the_exact_stdlib_iterator() -> None:
    from agentsweep.regex_engine import RE2_MAX_MATCHES, RE2_MIN_INPUT_CHARS
    from agentsweep.scanner import ENGINE_RULES, scan_text

    rule = next(
        pattern for rule_id, _display, pattern in ENGINE_RULES
        if rule_id == "aws-access-key"
    )
    original = rule._stdlib_pattern
    calls: list[str] = []

    class TrackingPattern:
        def finditer(self, text: str):
            calls.append(text)
            return original.finditer(text)

    text = "x" * RE2_MIN_INPUT_CHARS + " " + (
        "AKIAIOSFODNN7EXAMPLE " * (RE2_MAX_MATCHES + 1)
    )
    object.__setattr__(rule, "_stdlib_pattern", TrackingPattern())
    try:
        findings = scan_text(text)
    finally:
        object.__setattr__(rule, "_stdlib_pattern", original)

    assert calls == [text]
    assert sum(finding.rule == "aws-access-key" for finding in findings) == RE2_MAX_MATCHES + 1


@pytest.mark.skipif(
    importlib.util.find_spec("re2") is None,
    reason="requires optional google-re2 extra",
)
def test_scan_hot_path_does_not_compile_or_import_re2(monkeypatch) -> None:
    import re2

    from agentsweep.scanner import scan_text

    def fail_compile(*_args, **_kwargs):
        pytest.fail("RE2 compilation belongs to registry initialization, not scan_text")

    monkeypatch.setattr(re2, "compile", fail_compile)
    assert scan_text("AKIAIOSFODNN7EXAMPLE")
