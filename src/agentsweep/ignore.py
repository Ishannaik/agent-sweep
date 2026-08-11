"""`.agentsweepignore` — suppress known false positives.

Looked up in the scan root and the current directory. Each non-comment
line is one of:

    rule:<rule-id>            ignore every finding from that rule
    path:<pattern>            ignore findings whose relative path matches
    <relpath>:<line>:<rule>   ignore one exact finding (a "fingerprint")
    <literal>                 ignore any finding whose secret value matches

Path entries use fnmatch patterns, where * can match across path separators
and ** has no special recursive meaning. For example: path:*/fixtures/*

Fingerprints are what agentsweep prints next to each finding, so the
copy-paste path is: see a false positive, paste its fingerprint into
.agentsweepignore, done.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

IGNORE_FILENAME = ".agentsweepignore"


def fingerprint(relpath: str, line: int, rule: str) -> str:
    return f"{relpath}:{line}:{rule}"


class IgnoreSet:
    def __init__(self) -> None:
        self.rules: set[str] = set()
        self.fingerprints: set[str] = set()
        self.values: set[str] = set()
        self.globs: set[str] = set()
        self.sources: list[Path] = []

    def __bool__(self) -> bool:
        return bool(self.rules or self.fingerprints or self.values or self.globs)

    def add_line(self, raw: str) -> None:
        line = raw.strip()
        if not line or line.startswith("#"):
            return

        if line.startswith("rule:"):
            self.rules.add(line[len("rule:") :].strip())
            return

        # A fingerprint is "<path>:<line>:<rule>" — last segment a rule id,
        # second-to-last an integer line number. Anything else is a literal.
        parts = line.rsplit(":", 2)
        if len(parts) == 3 and parts[1].isdigit():
            self.fingerprints.add(line)
            return

        if line.startswith("path:"):
            glob = line[len("path:") :].strip()
            if glob:
                self.globs.add(glob)
            return

        self.values.add(line)

    def matches(self, rule: str, value: str, fp: str, relpath: str = "") -> bool:
        return (
            rule in self.rules
            or fp in self.fingerprints
            or value in self.values
            or any(
                fnmatch.fnmatch(relpath.replace("\\", "/"), glob) for glob in self.globs
            )
        )


def load(roots: list[Path]) -> IgnoreSet:
    """Merge .agentsweepignore from each given directory (root + cwd)."""
    seen: set[Path] = set()
    result = IgnoreSet()
    for root in roots:
        try:
            path = (root / IGNORE_FILENAME).resolve()
        except OSError:
            continue
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line in text.splitlines():
            result.add_line(line)
        result.sources.append(path)
    return result
