"""Subprocess helpers for import-time regex-engine parity tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


_BLOCK_RE2 = """
import sys
class _BlockRe2:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "re2":
            raise ImportError("blocked for no-RE2 coverage")
        return None
sys.meta_path.insert(0, _BlockRe2())
"""

_TEXT_SCAN = """
import hashlib
import json
import sys

data = json.load(sys.stdin)
from agentsweep import scanner

if data["force_all"]:
    scanner._triggered_indices = lambda _lowered: set(range(len(scanner.RULES)))

def normalize(finding):
    return [
        finding.rule,
        finding.display,
        finding.value,
        finding.masked,
        finding.span[0],
        finding.span[1],
    ]

results = [[normalize(finding) for finding in scanner.scan_text(text)] for text in data["texts"]]
encoded = json.dumps(results, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
print(json.dumps({
    "summary": scanner.ENGINE_SUMMARY,
    "prefilter_backend": scanner.PREFILTER_BACKEND,
    "inventory": scanner.ENGINE_INVENTORY if data["include_inventory"] else None,
    "results": results,
    "finding_hash": hashlib.sha256(encoded.encode()).hexdigest(),
}, ensure_ascii=False, sort_keys=True))
"""

_FILE_SCAN = """
import hashlib
import json
import sys
from pathlib import Path

data = json.load(sys.stdin)
from agentsweep import pipeline
from agentsweep.sources import CodexSource

pipeline._SCAN_WORKERS = data["workers"]
root = Path(data["root"])
source = CodexSource(root=root)
files = source.files()

def normalize(found):
    records = []
    for path, entries in found.items():
        for line, keypath, _value, finding in entries:
            records.append([
                path.relative_to(root).as_posix(), line, keypath,
                finding.rule, finding.display, finding.value, finding.masked,
                finding.span[0], finding.span[1],
            ])
    return records

attempts = []
for _ in range(data["repeats"]):
    found, strings, suppressed, truncated = pipeline._scan_all(
        source,
        files,
        ignores=None,
        exclude_rules=set(data["exclude_rules"]),
        only_rules=set(data["only_rules"]) or None,
    )
    records = normalize(found)
    encoded = json.dumps(records, ensure_ascii=False, separators=(",", ":"))
    attempts.append({
        "finding_hash": hashlib.sha256(encoded.encode()).hexdigest(),
        "records": records,
        "strings": strings,
        "suppressed": suppressed,
        "truncated": [path.relative_to(root).as_posix() for path in truncated],
    })

print(json.dumps({"summary": __import__("agentsweep.scanner", fromlist=["ENGINE_SUMMARY"]).ENGINE_SUMMARY,
                  "attempts": attempts}, ensure_ascii=False, sort_keys=True))
"""


def _run(program: str, payload: dict[str, Any], *, mode: str, block_re2: bool) -> dict[str, Any]:
    env = os.environ.copy()
    env["AGENTSWEEP_REGEX_ENGINE"] = mode
    command = _BLOCK_RE2 + program if block_re2 else program
    result = subprocess.run(
        [sys.executable, "-c", command],
        input=json.dumps(payload, ensure_ascii=False),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if result.returncode:
        raise AssertionError(
            f"scanner subprocess failed ({result.returncode}):\n{result.stderr}"
        )
    return json.loads(result.stdout)


def run_text_scan(
    texts: list[str],
    *,
    mode: str,
    force_all: bool = False,
    block_re2: bool = False,
    include_inventory: bool = False,
) -> dict[str, Any]:
    return _run(
        _TEXT_SCAN,
        {
            "texts": texts,
            "force_all": force_all,
            "include_inventory": include_inventory,
        },
        mode=mode,
        block_re2=block_re2,
    )


def run_file_scan(
    root: Path,
    *,
    mode: str,
    workers: int,
    repeats: int = 1,
    exclude_rules: list[str] | None = None,
    only_rules: list[str] | None = None,
    block_re2: bool = False,
) -> dict[str, Any]:
    return _run(
        _FILE_SCAN,
        {
            "root": str(root),
            "workers": workers,
            "repeats": repeats,
            "exclude_rules": exclude_rules or [],
            "only_rules": only_rules or [],
        },
        mode=mode,
        block_re2=block_re2,
    )
