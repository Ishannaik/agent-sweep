from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


MIN_AGE_SECONDS = 60

# A JSONL record ends at \r\n, \r or \n -- exactly the terminators
# bytes.splitlines() honours, which is how JsonlSource.iter_strings numbers
# records. str.splitlines() additionally breaks a *decoded* string on U+0085,
# U+2028 and U+2029, all of which RFC 8259 allows to appear raw inside a JSON
# string (and json.dumps(..., ensure_ascii=False) writes them through), so
# splitting the text that way renumbers records away from the line numbers the
# scan reported and splits one record into two invalid fragments.
_PHYSICAL_LINE_RE = re.compile(r"(?:[^\r\n]*(?:\r\n|\r|\n))|[^\r\n]+\Z")


def jsonl_lines(text: str) -> list[str]:
    """Split JSONL text into records, terminators included.

    Use this instead of ``str.splitlines()`` anywhere a line number has to mean
    the same record it meant while scanning.
    """
    return _PHYSICAL_LINE_RE.findall(text)


def audit_path() -> Path:
    # Resolved at call time, not import time, so tests that monkeypatch
    # HOME/USERPROFILE never append to the user's real audit log.
    return Path.home() / ".agentsweep" / "audit.jsonl"


class SafetyError(Exception):
    """A refusal to modify a file.

    `force_recoverable` is True only for the "active session" gates (file
    modified < MIN_AGE_SECONDS, or the agent appears to be running) that
    `--force` can legitimately bypass. Content-validation failures and the
    no-clobber backup check are never force-recoverable — `--force` can't fix
    them — so callers must not offer `--force` for those.
    """

    def __init__(self, *args, force_recoverable: bool = False, deferred: bool = False):
        super().__init__(*args)
        self.force_recoverable = force_recoverable
        # True when the file is merely not safe to rewrite *yet* (changed since
        # it was scanned, or a database under --settled): retry later, not an error.
        self.deferred = deferred


@dataclass
class WriteRecord:
    path: Path
    original_sha256: str
    new_sha256: str
    backup: Path | None
    bytes_before: int
    bytes_after: int
    unchanged: bool = False  # True when the redaction was a no-op (already done)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safety_check(
    path: Path, source_root: Path | Iterable[Path], force: bool = False
) -> None:
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

    contained = any(resolved == r or r in resolved.parents for r in resolved_roots)
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
                f"likely an active session. Close Claude Code or use --force.",
                force_recoverable=True,
            )


def safe_write(
    path: Path,
    new_content: str | bytes,
    backup: bool = True,
    fmt: str = "jsonl",
    sidecars: Sequence[Path] = (),
    in_place: bool = False,
    expect_sha256: str | None = None,
) -> WriteRecord:
    """Atomically replace `path`'s content with `new_content`.

    Guarantees:
      - Sidecars: files listed in `sidecars` (a SQLite database's `-wal` and
        `-shm`) are backed up alongside `path` and deleted once the replace
        lands. The caller MUST only pass sidecars whose committed contents
        are already folded into `new_content` — for SQLite that is what
        `Connection.backup()` does. Deleting them is what makes the
        redaction stick: a `-wal` left beside a replaced database still
        holds the pre-redaction plaintext, and SQLite replays it over the
        new file on the next open, silently restoring the secret.
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

    `in_place` (used by --settled) overwrites the existing inode instead of
    replacing it, after a compare-and-swap check against `expect_sha256` (the
    file's hash when its redactions were computed). os.replace gives the path
    a new inode: a writer that still holds the old one keeps appending to an
    unlinked file and that output is lost. Writing in place keeps the inode,
    so an appender's later writes land after the redacted content, and keeps
    ACLs, extended attributes and hard links. The residual window is the
    milliseconds between the final hash check and the write. A crash mid-write
    is recoverable from the same-directory guard copy written first.
    Databases (bytes content or sidecars) are never rewritten in place.
    """
    original_bytes = path.read_bytes()
    original_hash = _sha256(original_bytes)
    if expect_sha256 is not None and original_hash != expect_sha256:
        raise SafetyError(f"{path.name} changed since it was scanned", deferred=True)
    if in_place and (sidecars or isinstance(new_content, bytes)):
        raise SafetyError(
            f"{path.name} is a database; not rewritten while settled-mode runs",
            deferred=True,
        )

    if isinstance(new_content, bytes):
        new_bytes = new_content
    else:
        new_bytes = new_content.encode("utf-8")

        if fmt == "jsonl":
            _validate_jsonl(new_content)
        elif fmt == "json":
            _validate_json(new_content)
        elif fmt != "text":
            raise SafetyError(f"Unknown content format {fmt!r}; refusing to write")

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

    if new_bytes == original_bytes:
        # Idempotent no-op: the file is already in the target (redacted) state
        # — e.g. it was redacted in a previous pass, and re-applying the same
        # redaction changes nothing. Don't create a backup or rewrite; report
        # it so the caller renders a calm "already redacted" skip instead of a
        # confusing FAIL on the no-clobber backup check.
        return WriteRecord(
            path,
            original_hash,
            new_hash,
            None,
            len(original_bytes),
            len(new_bytes),
            unchanged=True,
        )

    # Sidecars are backed up before the replace and removed after it, so a
    # crash in between leaves the original database recoverable from the pair
    # of .bak files rather than half-retired.
    sidecar_backups: list[Path] = []

    backup_path: Path | None = None
    if backup:
        backup_path = path.with_name(path.name + ".bak")
        try:
            # O_EXCL makes the no-clobber check race-free; 0o600 keeps the
            # pre-redaction plaintext secrets in the backup unreadable to
            # other local users regardless of the umask.
            bak_fd = os.open(
                str(backup_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            raise SafetyError(
                f"Backup already exists: {backup_path}. "
                f"Resolve manually before re-running."
            ) from None
        with os.fdopen(bak_fd, "wb") as bak_file:
            bak_file.write(original_bytes)

        for sidecar in sidecars:
            sidecar_bak = sidecar.with_name(sidecar.name + ".bak")
            try:
                # 0o600 for the same reason as the main backup: a `-wal`
                # holds the very plaintext we are about to redact.
                sc_fd = os.open(
                    str(sidecar_bak),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                for done in sidecar_backups:
                    try:
                        done.unlink()
                    except OSError:
                        pass
                if backup_path.exists():
                    try:
                        backup_path.unlink()
                    except OSError:
                        pass
                raise SafetyError(
                    f"Backup already exists: {sidecar_bak}. "
                    f"Resolve manually before re-running."
                ) from None
            with os.fdopen(sc_fd, "wb") as sc_file:
                sc_file.write(sidecar.read_bytes())
            sidecar_backups.append(sidecar_bak)

    if in_place:
        try:
            _write_in_place(path, original_bytes, original_hash, new_bytes)
        except Exception:
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

    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        orig_stat = path.stat()
        with os.fdopen(fd, "wb") as f:
            f.write(new_bytes)
            f.flush()
            os.fsync(f.fileno())
        # Keep the file's permissions and timestamps: mkstemp creates 0600 with
        # mtime "now", which would change who can read the file and reorder
        # every agent's "recent sessions" list after a redaction pass.
        os.chmod(tmp_path, orig_stat.st_mode & 0o7777)
        os.utime(tmp_path, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
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
        for sidecar_bak in sidecar_backups:
            try:
                sidecar_bak.unlink()
            except OSError:
                pass
        raise

    # The replace landed. Every committed page these sidecars held is already
    # inside the bytes we just wrote, so they are now stale *and* still hold
    # pre-redaction plaintext. Retire them, or SQLite replays them on the next
    # open and the secret comes back.
    for sidecar in sidecars:
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            raise SafetyError(
                f"Redacted {path.name} but could not remove {sidecar.name}: {e}. "
                f"The stale WAL may restore the secret on next open — "
                f"delete it manually."
            ) from e

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
    for i, line in enumerate(jsonl_lines(content), 1):
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
            f.write(
                json.dumps(
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "path": str(record.path),
                        "original_sha256": record.original_sha256,
                        "new_sha256": record.new_sha256,
                        "backup": str(record.backup) if record.backup else None,
                        "bytes_before": record.bytes_before,
                        "bytes_after": record.bytes_after,
                    }
                )
                + "\n"
            )
    except OSError:
        pass


def _write_in_place(
    path: Path, original_bytes: bytes, original_hash: str, new_bytes: bytes
) -> None:
    """Overwrite `path`'s own inode with `new_bytes` (see safe_write in_place).

    A same-directory 0600 guard copy of the original is written (and the
    directory fsynced) first. It is removed only once the target is known to
    hold a complete version - the new bytes, the restored original, or the
    untouched original. If restoring fails too, the guard stays: it is then the
    only complete copy.
    """
    st = path.stat()
    fd, guard_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".guard"
    )
    guard = Path(guard_name)
    consistent = False
    try:
        with os.fdopen(fd, "wb") as g:
            g.write(original_bytes)
            g.flush()
            os.fsync(g.fileno())
        _fsync_dir(path.parent)
        with open(path, "r+b") as f:
            # Final compare-and-swap: anything written since the redactions
            # were computed means a writer is still active. Defer.
            if _sha256(f.read()) != original_hash:
                consistent = True  # not touched by us
                raise SafetyError(f"{path.name} changed while redacting", deferred=True)
            try:
                f.seek(0)
                f.write(new_bytes)
                f.truncate()
                f.flush()
                os.fsync(f.fileno())
                consistent = True
            except Exception:
                f.seek(0)
                f.write(original_bytes)
                f.truncate()
                f.flush()
                os.fsync(f.fileno())
                consistent = True  # restored
                raise
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
    finally:
        if consistent:
            try:
                guard.unlink()
            except OSError:
                pass
            _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
