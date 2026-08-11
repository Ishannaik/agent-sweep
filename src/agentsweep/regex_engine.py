"""Optional, per-rule RE2 selection for the scanner registry.

``google-re2`` is deliberately optional.  Python ``re`` remains the oracle:
RE2 is selected only when it compiles the pattern.  For rules whose Unicode
semantics can differ, the scanner sends non-ASCII text to the stdlib pattern;
ASCII text still uses RE2.  Rules that use ``\\b`` get a cheap stdlib
confirmation only after RE2 has found a non-ASCII candidate, because RE2 word
boundaries are ASCII while Python's default boundaries are Unicode-aware.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal, TypeAlias


EngineMode: TypeAlias = Literal["auto", "stdlib"]
BackendName: TypeAlias = Literal["re2", "stdlib"]
RawRule: TypeAlias = tuple[str, str, re.Pattern[str]]

_ENGINE_ENV = "AGENTSWEEP_REGEX_ENGINE"
_UNICODE_SHORTHANDS = frozenset("wWdDsS")
_INLINE_IGNORECASE = re.compile(r"\(\?[a-zA-Z-]*i[a-zA-Z-]*(?:[:)])")
# google-re2's Python wrapper is slower than ``re`` for tiny strings and for
# a single rule with thousands of results. These guards retain the compiled
# per-rule selection while taking the cheaper exact stdlib execution path in
# those measured cases. They never alter what a rule can match.
RE2_MIN_INPUT_CHARS = 512
RE2_MAX_MATCHES = 4

try:  # Optional dependency: importing AgentSweep must work without it.
    import re2 as _re2
except ImportError:  # pragma: no cover - covered in a no-extra subprocess
    _re2 = None


def requested_engine_mode() -> EngineMode:
    """Read the internal test/benchmark engine switch once at import time."""
    mode = os.environ.get(_ENGINE_ENV, "auto").lower()
    if mode not in {"auto", "stdlib"}:
        raise ValueError(f"{_ENGINE_ENV} must be 'auto' or 'stdlib', got {mode!r}")
    return mode  # type: ignore[return-value]  # checked against the literal set


def re2_version() -> str | None:
    """Return the installed distribution version without making it required."""
    if _re2 is None:
        return None
    try:
        return version("google-re2")
    except PackageNotFoundError:  # editable/embedded package with no metadata
        return "unknown"


RE2_AVAILABLE = _re2 is not None
RE2_VERSION = re2_version()


def _escaped_semantics(pattern: str) -> tuple[bool, bool]:
    """Return ``(needs_unicode_guard, needs_boundary_confirmation)``.

    A small lexer is safer than a regex here: ``\\\\w`` means a literal
    backslash plus ``w``, whereas ``\\w`` is Python's Unicode-aware shorthand.
    """
    has_boundary = False
    i = 0
    while i < len(pattern):
        if pattern[i] != "\\":
            i += 1
            continue
        if i + 1 == len(pattern):
            break
        escaped = pattern[i + 1]
        if escaped == "\\":
            i += 2
            continue
        if escaped in _UNICODE_SHORTHANDS or escaped == "B":
            return True, False
        if escaped == "b":
            has_boundary = True
        i += 2
    return False, has_boundary


def _guard_details(pattern: str) -> tuple[bool, bool, str | None]:
    """Return Unicode/boundary guards needed after a successful RE2 compile."""
    unicode_guard, boundary_guard = _escaped_semantics(pattern)
    reasons = []
    if unicode_guard:
        reasons.append(
            "RE2 ASCII character classes differ from Python re Unicode semantics"
        )
    if _INLINE_IGNORECASE.search(pattern):
        unicode_guard = True
        reasons.append("RE2 and Python re Unicode case-folding may differ")
    return unicode_guard, boundary_guard, "; ".join(reasons) or None


@dataclass(frozen=True)
class RulePattern:
    """Immutable adapter with the subset of ``re.Pattern`` the scanner uses."""

    rule_id: str
    pattern_text: str
    backend_name: BackendName
    fallback_reason: str | None
    compile_status: str
    semantic_guard: bool
    unicode_guard: bool
    guard_reason: str | None
    _compiled: Any
    _stdlib_pattern: re.Pattern[str]

    @property
    def pattern(self) -> str:
        """Keep the existing ``RULES``/``explain`` public shape intact."""
        return self.pattern_text

    def finditer(self, text: str, encoded: bytes | None = None) -> Iterable[Any]:
        """Find matches, optionally reusing scanner-owned ASCII UTF-8 bytes."""
        if self.backend_name == "stdlib" or len(text) < RE2_MIN_INPUT_CHARS:
            return self._stdlib_pattern.finditer(text)
        if self.unicode_guard and encoded is None:
            return self._stdlib_pattern.finditer(text)
        if not self.semantic_guard:
            source = (
                encoded if self.backend_name == "re2" and encoded is not None else text
            )
            return self._bounded_re2_finditer(source, text)
        if encoded is not None:
            # On ASCII, RE2 and Python agree on word boundaries, and byte
            # offsets equal character offsets; avoid per-hit Python checks.
            return self._bounded_re2_finditer(encoded, text)
        return self._verified_finditer(text, encoded)

    def _bounded_re2_finditer(self, source: str | bytes, text: str) -> Iterable[Any]:
        """Use RE2 normally, but avoid its Python-match-object dense-hit cost."""
        iterator = iter(self._compiled.finditer(source))
        first = next(iterator, None)
        if first is None:
            return ()
        matches = [first]
        for _ in range(RE2_MAX_MATCHES):
            candidate = next(iterator, None)
            if candidate is None:
                return matches
            matches.append(candidate)
        # Re-scan from the beginning rather than combining two iterators, so
        # zero-length and overlap behavior remains exactly Python ``re``.
        return self._stdlib_pattern.finditer(text)

    def _verified_finditer(
        self,
        text: str,
        encoded: bytes | None,
    ) -> Iterator[re.Match[str]]:
        """Filter RE2's ASCII ``\\b`` candidates with Python's exact boundary.

        The RE2 search remains the expensive discovery step.  Confirmation is
        only reached for a candidate match and returns the stdlib match object,
        preserving exact spans and values for the scanner.
        """
        pos = 0
        text_len = len(text)
        source = encoded if encoded is not None else text
        while pos <= text_len:
            candidate = self._compiled.search(source, pos)
            if candidate is None:
                return
            match = self._stdlib_pattern.match(text, candidate.start())
            if match is not None:
                yield match
                pos = match.end()
                if match.end() == match.start():
                    pos += 1
            else:
                # A non-ASCII word character can make RE2 see a boundary that
                # Python correctly rejects.  Advance one character so a later,
                # non-overlapping Python match is not skipped.
                pos = candidate.start() + 1


def _re2_options() -> Any:
    """Build compile options once per registry construction, outside scanning."""
    if _re2 is None:  # pragma: no cover - guarded by build_rule_registry
        raise RuntimeError("google-re2 options requested without google-re2")
    options = _re2.Options()
    options.log_errors = False
    return options


def _compile_rule(
    rule_id: str,
    stdlib_pattern: re.Pattern[str],
    mode: EngineMode,
    options: Any | None,
) -> RulePattern:
    text = stdlib_pattern.pattern
    if mode == "stdlib":
        return RulePattern(
            rule_id,
            text,
            "stdlib",
            "forced by AGENTSWEEP_REGEX_ENGINE=stdlib",
            "not-attempted",
            False,
            False,
            None,
            stdlib_pattern,
            stdlib_pattern,
        )
    if _re2 is None:
        return RulePattern(
            rule_id,
            text,
            "stdlib",
            "google-re2 is not installed",
            "unavailable",
            False,
            False,
            None,
            stdlib_pattern,
            stdlib_pattern,
        )

    if options is None:  # pragma: no cover - supplied by build_rule_registry
        raise RuntimeError("missing google-re2 compile options")
    try:
        compiled = _re2.compile(text, options=options)
    except _re2.error as exc:
        return RulePattern(
            rule_id,
            text,
            "stdlib",
            f"RE2 compile error: {exc}",
            "error",
            False,
            False,
            None,
            stdlib_pattern,
            stdlib_pattern,
        )

    unicode_guard, semantic_guard, guard_reason = _guard_details(text)
    return RulePattern(
        rule_id,
        text,
        "re2",
        None,
        "success",
        semantic_guard,
        unicode_guard,
        guard_reason,
        compiled,
        stdlib_pattern,
    )


def build_rule_registry(
    raw_rules: Iterable[RawRule],
    mode: EngineMode | None = None,
) -> list[tuple[str, str, RulePattern]]:
    """Select every backend once, before the scanner's hot path starts."""
    selected_mode = requested_engine_mode() if mode is None else mode
    if selected_mode not in {"auto", "stdlib"}:
        raise ValueError(f"unsupported regex engine mode: {selected_mode!r}")
    options = _re2_options() if selected_mode == "auto" and _re2 is not None else None
    return [
        (rule_id, display, _compile_rule(rule_id, pattern, selected_mode, options))
        for rule_id, display, pattern in raw_rules
    ]


def inventory(rules: Iterable[tuple[str, str, RulePattern]]) -> list[dict[str, object]]:
    """Return JSON-ready per-rule backend evidence for audits and benchmarks."""
    return [
        {
            "rule_id": rule_id,
            "pattern": pattern.pattern_text,
            "selected_backend": pattern.backend_name,
            "compile_status": pattern.compile_status,
            "fallback_reason": pattern.fallback_reason,
            "semantic_guard": pattern.semantic_guard,
            "unicode_guard": pattern.unicode_guard,
            "guard_reason": pattern.guard_reason,
            "short_input_fallback_chars": RE2_MIN_INPUT_CHARS,
            "dense_match_fallback_limit": RE2_MAX_MATCHES,
        }
        for rule_id, _display, pattern in rules
    ]


def summary(
    rules: Iterable[tuple[str, str, RulePattern]], requested: EngineMode
) -> dict[str, object]:
    """Return stable aggregate engine metadata without scanning any text."""
    entries = list(rules)
    re2_count = sum(pattern.backend_name == "re2" for _, _, pattern in entries)
    return {
        "requested_engine": requested,
        "effective_engine_mode": "mixed" if re2_count else "stdlib",
        "re2_available": RE2_AVAILABLE,
        "re2_version": RE2_VERSION,
        "re2_rule_count": re2_count,
        "stdlib_rule_count": len(entries) - re2_count,
        "fallback_rules": [
            rule_id
            for rule_id, _display, pattern in entries
            if pattern.backend_name == "stdlib"
        ],
        "short_input_fallback_chars": RE2_MIN_INPUT_CHARS,
        "dense_match_fallback_limit": RE2_MAX_MATCHES,
    }
