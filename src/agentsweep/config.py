"""Optional persistent default flags: ``agentsweep.toml`` / ``.agentsweeprc``.

Read, in order, from the current directory (``agentsweep.toml`` then
``.agentsweeprc``) and finally ``~/.config/agentsweep/config.toml``. The first
file found wins in full; values are never merged across files.

Only four keys are ever honored: ``source``, ``no_color``, ``format``,
``no_ignore`` — the flags the issue scoped as "safe to default silently".
CLI flags always win over the config file, and the config file over the
built-in default; see ``cli.py::_parse_run`` for the precedence merge.

``allow_production``, ``force``, and ``no_backup`` are never read from a
config file, even if present — those safety-gating flags must stay explicit
on every invocation so a stale or malicious config file can never silently
weaken a redaction safety gate.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

_PROJECT_FILENAMES = ("agentsweep.toml", ".agentsweeprc")

ALLOWED_KEYS = frozenset({"source", "no_color", "format", "no_ignore"})
FORBIDDEN_KEYS = frozenset({"allow_production", "force", "no_backup"})

# Expected TOML type per allowed key. A value of the wrong type (e.g.
# no_color = "false", a truthy non-empty string) is dropped with a warning
# rather than silently coerced — bool("false") is True in Python.
_EXPECTED_TYPES: dict[str, type] = {
    "source": str,
    "no_color": bool,
    "format": str,
    "no_ignore": bool,
}


def _user_config_path() -> Path:
    # Resolved lazily (not at import time) so tests can monkeypatch
    # HOME/USERPROFILE and so a long-lived process picks up a changed home.
    return Path.home() / ".config" / "agentsweep" / "config.toml"


def _find_config_path() -> Path | None:
    for name in _PROJECT_FILENAMES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            return candidate
    user_path = _user_config_path()
    if user_path.is_file():
        return user_path
    return None


def load_config() -> dict:
    """Return the allowed config keys found in the first config file located.

    Never raises: a missing, unreadable, or malformed file yields ``{}`` (with
    a warning on stderr for the malformed/unreadable case) so a broken config
    file can never break a normal scan.
    """
    path = _find_config_path()
    if path is None:
        return {}

    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(
            f"agentsweep: warning: ignoring unreadable config file {path}: {exc}",
            file=sys.stderr,
        )
        return {}

    forbidden_present = sorted(FORBIDDEN_KEYS & data.keys())
    if forbidden_present:
        joined = ", ".join(forbidden_present)
        print(
            f"agentsweep: warning: {path} sets {joined}, which a config file "
            "can never control — pass these on the command line instead.",
            file=sys.stderr,
        )

    result = {}
    for key in ALLOWED_KEYS:
        if key not in data:
            continue
        value = data[key]
        expected = _EXPECTED_TYPES[key]
        if not isinstance(value, expected):
            print(
                f"agentsweep: warning: {path} sets {key} to a "
                f"{type(value).__name__}, expected a {expected.__name__}; "
                "ignoring this key.",
                file=sys.stderr,
            )
            continue
        result[key] = value
    return result
