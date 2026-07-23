# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CLAUDE_CONFIG_DIR` support so Claude Code profiles outside the default
  `~/.claude` (e.g. `~/.claude-personal`) can be scanned (#63)
- SARIF 2.1.0 output (`--format sarif`) for GitHub code scanning and other
  SARIF viewers (#58)
- `fix --all`: guided multi-source redaction (#59)
- Dockerfile and container usage docs (#27, #62)
- Crush (Charm) agent source (#57)
- Google OAuth client secret and service-account key detectors (#104)
- Additional LLM-provider secret detectors (#109)
- Pre-commit hook (`.pre-commit-hooks.yaml`) (#75)
- Warning for leftover `.bak` files that still hold secrets (#74)
- `--no-color` flag; also honors the `NO_COLOR` env var (#78, #97, #101)
- Bash/zsh/fish and PowerShell shell completions (#31, #56)
- Man page for the `agentsweep` command (#105)
- `pytest-benchmark` harness for scan hot paths (#94)

### Fixed
- CRLF line endings are now preserved through redaction rewrites (#54)
- Shell-completion command contract (#53)

### Changed
- `scan --all` parallelized across sources for faster multi-source runs
  (#92, #103)

### CI / Infra
- mypy static type checking (#89)
- Enforced test-coverage threshold (#96)
- CodeQL, Dependabot, and SHA-pinned Actions for supply-chain hardening
- macOS and ARM Linux added to the test matrix
- `deptry` + `vulture` dead-code/dependency checks (#87, #108)
- Bandit SAST job, all findings triaged (#106)

## [0.1.9] - 2026-06-13
### Fixed
- Idempotent redaction retries; stop offering `--force` when it can't help

## [0.1.8] - 2026-06-13
### Added
- In-app contribution nudges

### Changed
- BIP-39 wordlist stored as a compact joined string

## [0.1.7] - 2026-06-13
### Added
- 13 more agent sources (29 total)
- Experimental-source flag for sources whose history path/format is
  inferred rather than verified against a real install

## [0.1.6] - 2026-06-13
### Added
- Discord bot token detector (id.timestamp.hmac base64url) (#8)
- Discord webhook URL detector
- Kilo Code, Roo Code, and Open Interpreter sources
- "All sources" option in the interactive scan picker
- `purge` verb for stale `.bak` backups; new backups created `0600` (#7)
- `uv.lock` for reproducible dev installs
- Pull-request and issue templates (#11)

### Fixed
- TUI arrow keys misread as quit on Unix terminals (#5)
- `--fix` now works for markdown and whole-file JSON histories, fail-closed
  (#3)
- Windows CI: pty/termios imports moved inside Unix-only functions (#9)
- `os.read` buffer tightened from 16 to 6 bytes in `_read_key_unix`

### Changed
- Menu elif-ladders collapsed into dispatch tables; redact rendering
  deduplicated (#10)

## [0.1.5] - 2026-06-12
### Added
- OpenClaw, Hermes, and Goose agent sources
- Mermaid pipeline diagram in README (5-stage flow, scan vs. fix paths)

### Fixed
- SQLite sources now back up before mutating, via the `sqlite3.backup()` API

### Changed
- Sources modularized into the `sources/` package

## [0.1.4] - 2026-06-12
### Fixed
- Skip a redundant double-scan on REDACT

### Changed
- TUI polish; 7-option menu

## [0.1.3] - 2026-06-12
### Added
- Interactive TUI picker
- Parallel file scanning
- 10 total agent sources

## [0.1.2] - 2026-06-12
### Added
- Codex, OpenCode, Cursor, Windsurf, Aider, Cline, Gemini CLI,
  Continue (VS Code), and GitHub Copilot Chat agent sources
- `python -m agentsweep` support via `__main__.py`
- Preflight checks for a running agent process
- Background update-check on TTY launches, with `--update` flag
- PyPI publish workflow triggered on version tags

### Fixed
- Discovery spinner now shows while walking large folders
- Removed `force-include` from `pyproject.toml` — it was breaking editable
  installs

## [0.1.1]
### Added
- `asweep` short alias for the `agentsweep` command

## [0.1.0] - Initial release
### Added
- Core scan/redact pipeline for Claude Code history
- Interactive menu mode with confirmation and undo
- 131 initial secret-pattern detectors, later expanded to 189
- Keyword pre-filter for faster scanning
- `pip install` / `uvx` packaging and CI

[Unreleased]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.9...HEAD
[0.1.9]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Ishannaik/agent-sweep/releases/tag/v0.1.0
