"""Rotating scan tips — shown during long scans to keep things lively."""
from __future__ import annotations



TIPS: list[str] = [
    "Scanning is read-only and safe; only --fix ever writes anything",
    "agentsweep undo restores every .bak backup in one command",
    "Add a finding's fingerprint to .agentsweepignore to silence a false positive",
    "agentsweep -o findings.json saves results instead of flooding your terminal",
    "agentsweep --json pipes clean JSON into jq or any downstream tool",
    "Type REDACT to confirm in-place redaction — backups are always kept",
    "agentsweep scan --source codex scans your OpenAI Codex history too",
    "agentsweep scan --all aggregates every agent; --detected limits to installed ones",
    "Seed phrases are validated by BIP-39 checksum, so prose never false-positives",
    "Set AGENTSWEEP_NO_ANIM=1 to disable animations and the live progress bar",
    "Use --root /path/to/copy to scan an offline archive without touching production",
    "Rotated your keys? agentsweep purge deletes the .bak files holding the plaintext originals",
    "--no-ignore bypasses .agentsweepignore — useful to audit what you've silenced",
    "The audit log at ~/.claude/agentsweep-audit.jsonl records every write with SHA256",
    "agentsweep --source claude-code is the default; omit --source to scan Claude Code",
    "After scanning, agentsweep shows the rotation URL for each detected provider",
]



def tip_for(n: int) -> str:
    """Return tip at index n (mod len), cycling deterministically."""
    return TIPS[n % len(TIPS)]
