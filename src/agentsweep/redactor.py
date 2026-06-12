from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


MIN_AGE_SECONDS = 60


def audit_path() -> Path:
    # Resolved at call time, not import time, so tests that monkeypatch
    # HOME/USERPROFILE never append to the user's real audit log.
    return Path.home() / ".agentsweep" / "audit.jsonl"


class SafetyError(Exception):
    pass


@dataclass
class WriteRecord:
    path: Path
    original_sha256: str
    new_sha256: str
    backup: Path | None
    bytes_before: int
    bytes_after: int


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safety_check(path: Path, source_root: Path | Iterable[Path],
                 force: bool = False) -> None:
    """Raise SafetyError if `path` is not safe to modify.

    Refuses: paths outside the source's root(s), symlinks, and files modified
    within MIN_AGE_SECONDS (likely an active session). `force=True` bypasses
    only the mtime check; path-containment and symlink checks are never
    bypassed. `source_root` may be a single Path or, for sources whose
    history spans several trees (Cursor agent transcripts, Windsurf
    memories), an iterable of them — containment in any one suffices.
    """
    roots = [source_root] if isinstance(source_root, Path) else list(source_root)

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as e:
        raise SafetyError(f"Cannot resolve path: {e}") from e

    resolved_roots: list[Path] = []
    for root in roots:
        try:
            resolved_roots.append(root.resolve(strict=True))
        except (OSError, RuntimeError):
            continue  # a secondary tree may legitimately not exist
    if not resolved_roots:
        raise SafetyError("Cannot resolve any source root")

    contained = any(
        resolved == r or r in resolved.parents for r in resolved_roots
    )
    if not contained:
        raise SafetyError(
            f"Refusing to modify path outside source root(s): {path} "
            f"(resolves to {resolved}, root(s): "
            f"{', '.join(str(r) for r in resolved_roots)})"
        )

    if path.is_symlink():
        raise SafetyError(f"Refusing to modify symlink: {path}")

    if not force:
        age = time.time() - path.stat().st_mtime
        if age < MIN_AGE_SECONDS:
            raise SafetyError(
                f"File modified {age:.0f}s ago (minimum {MIN_AGE_SECONDS}s); "
                f"likely an active session. Close Claude Code or use --force."
            )


def safe_write(path: Path, new_content: str | bytes,
               backup: bool = True, fmt: str = "jsonl") -> WriteRecord:
    """Atomically replace `path`'s content with `new_content`.

    Guarantees:
      - Post-write validation (str content), selected by `fmt`:
          "jsonl" — every non-empty line must parse as JSON and the line
                    count must match the original (the default);
          "json"  — the whole content must parse as one JSON document
                    (re-serialization may legitimately reflow lines, so no
                    line-count check);
          "text"  — the line count must match the original (markdown and
                    plaintext histories, where redaction replaces whole
                    lines 1:1).
        bytes content is the contract for binary formats (SQLite), where
        these checks are meaningless — the producing source MUST validate
        the bytes itself (e.g. PRAGMA integrity_check on the rewritten
        copy) before handing them over; `fmt` is ignored.
      - Atomic replacement: writes to a sibling tempfile with fsync, then
        os.replace. A crash at any point leaves either the complete old file
        or the complete new file on disk — never a torn write.
      - Backup: writes `<path>.bak` before replacement (refuses if one
        already exists, to avoid clobbering a prior backup).
      - Audit: appends a record to ~/.agentsweep/audit.jsonl with
        SHA256 of both versions.
    """
    original_bytes = path.read_bytes()
    original_hash = _sha256(original_bytes)

    if isinstance(new_content, bytes):
        new_bytes = new_content
    else:
        new_bytes = new_content.encode("utf-8")

        if fmt == "jsonl":
            _validate_jsonl(new_content)
        elif fmt == "json":
            _validate_json(new_content)
        elif fmt != "text":
            raise SafetyError(
                f"Unknown content format {fmt!r}; refusing to write"
            )

        if fmt != "json":
            original_text = original_bytes.decode("utf-8")
            original_line_count = len(original_text.splitlines(keepends=True))
            new_line_count = len(new_content.splitlines(keepends=True))
            if original_line_count != new_line_count:
                raise SafetyError(
                    f"Line count changed after redaction "
                    f"({original_line_count} -> {new_line_count}); refusing to write"
                )

    new_hash = _sha256(new_bytes)

    backup_path: Path | None = None
    if backup:
        backup_path = path.with_name(path.name + ".bak")
        if backup_path.exists():
            raise SafetyError(
                f"Backup already exists: {backup_path}. "
                f"Resolve manually before re-running."
            )
        backup_path.write_bytes(original_bytes)

    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(new_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        if backup_path is not None and backup_path.exists():
            try:
                backup_path.unlink()
            except OSError:
                pass
        raise

    record = WriteRecord(
        path=path,
        original_sha256=original_hash,
        new_sha256=new_hash,
        backup=backup_path,
        bytes_before=len(original_bytes),
        bytes_after=len(new_bytes),
    )
    _append_audit(record)
    return record


def _validate_json(content: str) -> None:
    try:
        json.loads(content)
    except json.JSONDecodeError as e:
        raise SafetyError(
            f"Post-redaction validation failed: content is not valid JSON "
            f"({e.msg} at line {e.lineno} col {e.colno}). Refusing to write."
        ) from e


def _validate_jsonl(content: str) -> None:
    for i, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as e:
            raise SafetyError(
                f"Post-redaction validation failed: line {i} is not valid JSON "
                f"({e.msg} at col {e.colno}). Refusing to write."
            ) from e


def _append_audit(record: WriteRecord) -> None:
    try:
        target = audit_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "path": str(record.path),
                "original_sha256": record.original_sha256,
                "new_sha256": record.new_sha256,
                "backup": str(record.backup) if record.backup else None,
                "bytes_before": record.bytes_before,
                "bytes_after": record.bytes_after,
            }) + "\n")
    except OSError:
        pass
