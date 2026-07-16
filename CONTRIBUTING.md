# Contributing

## PRs we want right now

**New `Source` adapters.** Every AI coding agent stores history somewhere. agentsweep currently understands ~30 agents (run `agentsweep list-sources` for the full, current list) — if you write code against something not on that list, a small adapter makes agentsweep work for your tool too.

**New detection rules, with rotation guidance and a fixture.** We're actively taking new secret patterns — see [#23](https://github.com/Ishannaik/agent-sweep/issues/23) (missing LLM-provider API keys: xAI, Groq, Mistral, Cohere, DeepSeek, OpenRouter, Together, Fireworks) and [#30](https://github.com/Ishannaik/agent-sweep/issues/30) (Google service-account keys and OAuth client secrets) for examples of the kind of rule PRs we want.

**Tests, packaging, and safety hardening** around the scan/redact pipeline are always welcome.

## The `Source` interface

Sources live in the `src/agentsweep/sources/` package (`_base.py`, `_core.py`, `_extended.py`, `_vscode.py`, `_more.py`, `_community.py`) and are re-exported from `sources/__init__.py`. Every adapter subclasses `Source` (see `_base.py`):

```python
class Source(ABC):
    name: str
    display_name: str
    root: Path
    process_markers: tuple[str, ...] = ()
    experimental: bool = False

    def files(self) -> list[Path]:
        """Every history file to scan under this source's root."""

    def iter_strings(self, path: Path) -> Iterator[tuple[int, KeyPath, str]]:
        """Yield (line_number, keypath, string_value) for every string.

        line_number is 1-indexed. keypath locates the string inside the file's
        structure (e.g. ["message", "content", 0, "text"] for Claude Code).
        """

    def apply_redactions(
        self,
        path: Path,
        redactions: list[tuple[int, KeyPath, str]],
    ) -> str | bytes:
        """Return the full new file content with strings replaced.

        str for text-based formats, bytes for binary formats like SQLite.
        MUST preserve structure per content_format() (JSONL, whole-file JSON,
        or line-count-preserving text) — the redactor's post-write validation
        will reject a write that doesn't.
        """
```

`process_markers` feeds `preflight.is_agent_running()`, a best-effort check that warns if the source's agent is currently running (to avoid redacting a file mid-write). Set `experimental = True` if the storage path/format was derived from research but not yet confirmed against a real install of the tool.

## Adding a new source — checklist

1. Subclass `Source` in the right file under `src/agentsweep/sources/` (or add a new module for a new family of agents).
2. Register it in the `SOURCES` dict in `sources/__init__.py`, and re-export it from that file's `__all__`.
3. If the agent has a detectable running process, add its `*_MARKERS` tuple to `preflight.py` and set `process_markers` on the class.
4. Update the hardcoded agent count in `ui/widgets.py`'s `menu_options()` (`"all N agents in parallel"`) and in README.md's supported-agents line/table.
5. Add an anonymized fixture under `tests/fixtures/<your-source>/sample.<ext>` and a round-trip test covering `iter_strings` (finds a planted secret) and `apply_redactions` (preserves structure).
6. Document the history location in README.md.
7. Open the PR, referencing which version of the agent you tested against.

## Adding a new detection rule — checklist

1. Add a `(rule_id, display_name, compiled_regex)` tuple to `RULES` in `scanner.py`.
2. Add matching guidance to `ROTATION_GUIDANCE` in `scanner.py` (how to rotate/revoke that credential type).
3. Add a synthetic (non-live-looking) fixture value to `FIXTURES` in `tests/test_ported_rules.py` — split across adjacent string literals so the file itself never contains a contiguous secret-shaped token (GitHub push protection will flag it otherwise).
4. Run the suite; `test_ported_rules.py` enforces that every rule has both a fixture and rotation guidance.

## Running tests
