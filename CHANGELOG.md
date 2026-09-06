# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add a verified Grok Build (xAI) JSONL source (`grok-build`) for `~/.grok/sessions/` transcripts (`chat_history.jsonl`, `updates.jsonl`, `events.jsonl`; honors `$GROK_HOME`). Distinct from experimental Grok CLI (`grok-cli` / superagent-ai sqlite `grok.db`); they share `~/.grok` but scan different files, and `auth.json` is never opened.
- Add a `list-sources` command with machine-readable and detected-source output.
- Add multi-source `scan --all` and guided `fix --all`, including `--detected`.
- Add Datasette `llm` and Crush history sources, and honor `CLAUDE_CONFIG_DIR` for Claude profile roots.
- Add command completion for Bash, Zsh, Fish, and PowerShell.
- Add `explain <rule-id>` and `explain --list` for redaction rules.
- Add repeatable `--only-rule` and `--exclude-rule` rule filtering.
- Add SARIF 2.1.0 scan output.
- Add JSON blast-radius reporting through `--report`.
- Add finding rollups through `--stats`.
- Add custom validated redaction markers through `fix --redact-with`.
- Add persistent safe TOML defaults with CLI precedence, and warn about and ignore safety-gating flags from config files.
- Add `--no-color` and `NO_COLOR` support across human output and update notices, treating `FORCE_COLOR=0` as not forcing color.
- Add secret detectors for Google OAuth and service-account credentials, Cohere, DeepSeek, Fireworks AI, Groq, Mistral AI, OpenRouter, Together AI, xAI/Grok, and Docker Hub personal-access tokens.
- Add a non-root Docker image, a pre-commit hook, and a Unix man page.
- Flash the live scan finding count when new secrets are detected.

### Changed

- Run all-source discovery and scanning concurrently while retaining deterministic output.
- Reduce `--version` startup work by avoiding source, UI, completion, and update-network imports.

### Fixed

- Scan current OpenCode SQLite schemas and fail loudly when a known table has none of its expected text columns.
- Bound Aider discovery by pruning cache and vendor trees, while retaining `.config` histories and warning when the 12-level depth cap requires `--root`.
- Preserve CRLF line endings during redaction.

### Security

- Prevent SQLite WAL/SHM sidecars from retaining or replaying plaintext after redaction, and include sidecar backups in undo and purge.
- Warn that leftover `.bak` files may still retain plaintext secrets.
- Quote dynamic SQLite identifiers throughout scanning and redaction.
- Harden repository and release automation with least-privilege permissions, immutable Action pins, CodeQL, and OpenSSF Scorecard.

## [0.1.9] - 2026-06-13

### Fixed

- Make repeated redaction idempotent: already-redacted files skip without another backup or rewrite, while a stale `.bak` with a pending change still fails.
- Offer `--force` only for active-session and mtime gates it can bypass.

## [0.1.8] - 2026-06-13

### Added

- Add an in-app open-source star/contribution nudge and a Star/contribute menu action.

### Changed

- Store the BIP-39 word list as a compact joined string without changing its bytes.

## [0.1.7] - 2026-06-13

### Added

- Add Warp, Grok CLI, Kiro CLI, Zed, Trae, Void, PearAI, Qwen Code, Codebuff, Plandex, Junie, Mentat, and JetBrains AI Assistant sources, bringing the total to 29.

### Changed

- Mark those research-derived source paths and formats as experimental, and show that status in the picker and scan notice.

## [0.1.6] - 2026-06-13

### Added

- Detect Discord bot tokens.
- Detect Discord webhook URLs.
- Add Kilo Code, Roo Code, and Open Interpreter sources.
- Add an All sources action to the interactive picker.
- Add the `purge` verb for deleting `.bak` files after key rotation.

### Changed

- Create `.bak` files with mode `0600`.
- Bound scan work to 50 MB per file and 1 MB per string, reporting capped files instead of hanging.

### Fixed

- Stop Unix arrow keys from being read as quit.
- Keep Unix-only imports from breaking Windows.
- Apply format-aware, fail-closed validation when redacting Markdown and whole-file JSON histories.

## [0.1.5] - 2026-06-12

### Added

- Add OpenClaw, Hermes Agent, and Goose sources with their documented path overrides.

### Changed

- Split source implementations into the `sources/` package.

### Fixed

- Back up SQLite databases with `sqlite3.backup()` before mutation.
- Move the audit log to `~/.agentsweep/audit.jsonl`.
- Honor `AGENTSWEEP_NO_UPDATE` for disabling startup update checks.
- Correct keyword-prefilter overrides for five rules.

## [0.1.4] - 2026-06-12

### Changed

- Polish the TUI and simplify it to a seven-action menu.

### Fixed

- Reuse existing findings after `REDACT` instead of scanning twice.

## [0.1.3] - 2026-06-12

### Added

- Add an interactive arrow-key source picker.
- Scan files in parallel.
- Support ten agent sources.

## [0.1.2] - 2026-06-12

### Added

- Add Codex, OpenCode, Cursor, Windsurf, Aider, Cline, Gemini CLI, Continue, and GitHub Copilot Chat sources.
- Support `python -m agentsweep`.
- Add running-agent preflight checks.
- Add background and explicit update checking.
- Publish to PyPI from version tags.

### Fixed

- Show discovery progress while walking large folders.
- Remove the `force-include` setting that broke editable installs.

## [0.1.1] - 2026-06-11

### Added

- Add the `asweep` short command alias.

## [0.1.0] - 2026-06-11

### Added

- Add the core scan/redact pipeline for Claude Code history.
- Add interactive confirmation and undo.
- Add the initial secret-detector set and checksum-validated seed-phrase detection.
- Add the keyword prefilter.
- Make the project installable through `pip` and `uvx`, with CI coverage.

[Unreleased]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.9...HEAD
[0.1.9]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Ishannaik/agent-sweep/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Ishannaik/agent-sweep/compare/0f5c488e84262137965114cac6c12676f456a4ac...v0.1.2
[0.1.1]: https://github.com/Ishannaik/agent-sweep/compare/b3de35e6f04df8f5a1e62dea793c1036c5969a1f...0f5c488e84262137965114cac6c12676f456a4ac
[0.1.0]: https://github.com/Ishannaik/agent-sweep/commit/b3de35e6f04df8f5a1e62dea793c1036c5969a1f
