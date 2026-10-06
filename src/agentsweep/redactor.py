from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .sources import Source


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

    def __init__(self, *args, force_recoverable: bool = False):
        super().__init__(*args)
        self.force_recoverable = force_recoverable


@dataclass
class WriteRecord:
    path: Path
    original_sha256: str
    new_sha256: str
    backup: Path | None
    bytes_before: int
    bytes_after: int
    unchanged: bool = False  # True when the redaction was a no-op (already done)


@dataclass(frozen=True)
class RedactionTarget:
    """One scanner finding and its expected decoded replacement."""

    line: int
    keypath: tuple[object, ...]
    original: str
    replacement: str
    rule: str
    span: tuple[int, int]


@dataclass(frozen=True)
class RedactionVerification:
    """Semantic proof that a source applied its selected redactions."""

    source: Source
    targets: tuple[RedactionTarget, ...]


@dataclass(frozen=True)
class _DecodedStrings:
    by_location: dict[tuple[int, tuple[object, ...]], tuple[object, str]]
    by_identity: dict[object, str]


@dataclass(frozen=True)
class _VerificationBaseline:
    values: dict[object, str]
    expected: dict[object, str]
    allowed: Counter[tuple[object, str, str]]


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
    *,
    verification: RedactionVerification | None = None,
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
      - When `verification` is supplied, the persisted bytes are read back
        and the source re-decodes the file. Every selected location must
        hold its intended replacement; only pre-existing, unselected fired
        detector matches may remain at the same logical location.
      - Atomic replacement: writes to a sibling tempfile with fsync, then
        os.replace. A crash at any point leaves either the complete old file
        or the complete new file on disk — never a torn write.
      - Backup: writes `<path>.bak` before replacement (refuses if one
        already exists, to avoid clobbering a prior backup).
      - Audit: appends a record to ~/.agentsweep/audit.jsonl with
        SHA256 of both versions, only after successful verification.
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

    baseline = (
        _prepare_redaction_verification(path, verification)
        if verification is not None
        else None
    )
    new_hash = _sha256(new_bytes)

    if new_bytes == original_bytes:
        if verification is not None:
            _verify_redaction(path, new_bytes, verification, baseline)
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

    # Sidecars must share the main file's recovery state: backup writes
    # persistent .bak copies, while verified no-backup writes prepare and fsync
    # ephemeral recovery copies before replacing anything.
    sidecar_backups: list[Path] = []
    sidecar_recoveries: list[tuple[Path, Path]] = []

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

    recovery_path: Path | None = None
    if verification is not None and not backup:
        recovery_path = _prepare_recovery(path, original_bytes)
        try:
            for sidecar in sidecars:
                sidecar_recoveries.append(
                    (sidecar, _prepare_recovery(sidecar, sidecar.read_bytes()))
                )
        except Exception as e:
            for _sidecar, recovery in sidecar_recoveries:
                try:
                    recovery.unlink()
                except OSError:
                    pass
            try:
                recovery_path.unlink()
            except OSError:
                pass
            if isinstance(e, SafetyError):
                raise
            raise SafetyError(
                "Could not persist recovery copy before redaction; refusing to write"
            ) from e

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
        for stale_backup in [
            *sidecar_backups,
            *([recovery_path] if recovery_path is not None else []),
            *(recovery for _sidecar, recovery in sidecar_recoveries),
        ]:
            try:
                stale_backup.unlink()
            except OSError:
                pass
        raise

    _retire_sidecars(path, sidecars)

    if verification is not None:
        try:
            _verify_redaction(path, new_bytes, verification, baseline)
            _retire_sidecars(path, verification.source.sidecars(path))
        except Exception as verification_error:
            try:
                if recovery_path is not None:
                    _restore_prepared_recovery(path, recovery_path)
                    _restore_prepared_sidecars(sidecar_recoveries)
                elif backup_path is not None:
                    _restore_from_backup(path, backup_path)
                    _restore_sidecars_from_backups(sidecars, sidecar_backups)
                else:  # pragma: no cover - guarded by recovery preparation
                    raise SafetyError("No recovery copy is available")
            except SafetyError as rollback_error:
                raise SafetyError(
                    "Post-write redaction verification failed and rollback "
                    f"failed; {rollback_error}"
                ) from rollback_error
            raise SafetyError(
                "Post-write redaction verification failed; original content "
                "was restored"
            ) from verification_error

    if recovery_path is not None:
        try:
            recovery_path.unlink()
        except OSError as cleanup_error:
            try:
                _restore_prepared_recovery(path, recovery_path)
            except SafetyError as rollback_error:
                raise SafetyError(
                    "Verified redaction could not remove its recovery copy; "
                    f"{rollback_error}"
                ) from rollback_error
            raise SafetyError(
                "Verified redaction was rolled back because its recovery copy "
                "could not be removed"
            ) from cleanup_error

    for _sidecar, sidecar_recovery in sidecar_recoveries:
        try:
            sidecar_recovery.unlink()
        except OSError as e:
            raise SafetyError(
                "Verified redaction could not remove its SQLite sidecar "
                f"recovery copy; complete recovery copy retained at "
                f"{sidecar_recovery}"
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


def _retire_sidecars(path: Path, sidecars: Iterable[Path]) -> None:
    """Remove stale SQLite sidecars after their pages were folded into ``path``."""
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


def _prepare_redaction_verification(
    path: Path,
    verification: RedactionVerification,
) -> _VerificationBaseline:
    """Capture the only residual matches a verified write may retain."""
    from .scanner import DETECTOR_IDS, RULES

    known_rules = {rule for rule, _display, _pattern in RULES}
    known_rules.update(DETECTOR_IDS)
    fired_rules = {target.rule for target in verification.targets}
    if not verification.targets or not fired_rules <= known_rules:
        raise SafetyError(
            "Redaction verification has no valid fired detector set; refusing to write"
        )

    before = _decoded_strings(
        verification.source,
        path,
        _verification_target_keypaths(verification),
    )
    expected: dict[object, str] = {}
    selected: set[tuple[object, str, tuple[int, int]]] = set()
    for target in verification.targets:
        location = (target.line, target.keypath)
        actual = before.by_location.get(location)
        if actual is None or actual[1] not in {
            target.original,
            target.replacement,
        }:
            raise SafetyError(
                "Redaction verification could not confirm selected source "
                "content; refusing to write"
            )
        identity, value = actual
        already_replaced = value == target.replacement
        prior = expected.setdefault(identity, target.replacement)
        if prior != target.replacement:
            raise SafetyError(
                "Redaction verification has conflicting selected locations; "
                "refusing to write"
            )
        matches = _fired_matches(target.original, {target.rule})
        if not any(
            rule == target.rule
            and span == target.span
            and value == target.original[span[0] : span[1]]
            for rule, value, span in matches
        ):
            raise SafetyError(
                "Redaction verification could not confirm a selected detector "
                "match; refusing to write"
            )
        if not already_replaced:
            selected.add((identity, target.rule, target.span))

    allowed: Counter[tuple[object, str, str]] = Counter()
    for identity, value in before.by_identity.items():
        for rule, match_value, span in _fired_matches(value, fired_rules):
            if (identity, rule, span) not in selected:
                allowed[(identity, rule, match_value)] += 1
    return _VerificationBaseline(before.by_identity, expected, allowed)


def _verify_redaction(
    path: Path,
    new_bytes: bytes,
    verification: RedactionVerification,
    baseline: _VerificationBaseline | None,
) -> None:
    if baseline is None:
        raise SafetyError("Redaction verification state is unavailable")
    try:
        if path.read_bytes() != new_bytes:
            raise SafetyError("Persisted bytes differ from the redaction output")
        after = _decoded_strings(
            verification.source,
            path,
            _verification_target_keypaths(verification),
        )
        if after.by_identity.keys() != baseline.values.keys():
            raise SafetyError(
                "Redaction verification could not re-read every logical source location"
            )
        for identity, replacement in baseline.expected.items():
            if after.by_identity.get(identity) != replacement:
                raise SafetyError(
                    "Redaction verification could not confirm an intended replacement"
                )

        fired_rules = {target.rule for target in verification.targets}
        residuals: Counter[tuple[object, str, str]] = Counter(
            (identity, rule, value)
            for identity, text in after.by_identity.items()
            for rule, value, _span in _fired_matches(text, fired_rules)
        )
        if residuals - baseline.allowed:
            raise SafetyError(
                "Redaction verification found a selected or new residual detector match"
            )
    except SafetyError:
        raise
    except Exception as e:
        raise SafetyError(
            "Redaction verification could not read or scan persisted content"
        ) from e


def _verification_target_keypaths(
    verification: RedactionVerification,
) -> frozenset[tuple[object, ...]]:
    return frozenset(target.keypath for target in verification.targets)


def _decoded_strings(
    source: Source,
    path: Path,
    target_keypaths: frozenset[tuple[object, ...]],
) -> _DecodedStrings:
    try:
        entries = list(source.iter_strings(path))
        by_location: dict[tuple[int, tuple[object, ...]], tuple[object, str]] = {}
        for line, keypath, value in entries:
            location = (line, tuple(keypath))
            if location in by_location or not isinstance(value, str):
                raise SafetyError(
                    "Redaction verification received invalid logical source locations"
                )
            by_location[location] = (None, value)

        identities = source.verification_identities(
            path,
            entries,
            target_keypaths,
        )
        if len(identities) != len(entries):
            raise SafetyError(
                "Redaction verification received incomplete source identities"
            )
        by_identity: dict[object, str] = {}
        for (line, keypath, value), identity in zip(entries, identities):
            location = (line, tuple(keypath))
            if identity in by_identity:
                raise SafetyError(
                    "Redaction verification found ambiguous stable source identities"
                )
            by_location[location] = (identity, value)
            by_identity[identity] = value
        return _DecodedStrings(by_location, by_identity)
    except SafetyError:
        raise
    except Exception as e:
        raise SafetyError("Redaction verification could not read source content") from e


def _fired_matches(
    text: str,
    fired_rules: set[str],
) -> list[tuple[str, str, tuple[int, int]]]:
    """Run every selected detector directly, without scanner overlap dedupe."""
    try:
        from .mnemonic import detect_mnemonics
        from .scanner import RULES

        matches = [
            (rule, match.group(0), (match.start(), match.end()))
            for rule, _display, pattern in RULES
            if rule in fired_rules
            for match in pattern.finditer(text)
        ]
        if "bip39-mnemonic" in fired_rules:
            matches.extend(
                (finding.rule, finding.value, finding.span)
                for finding in detect_mnemonics(text)
            )
        return matches
    except Exception as e:
        raise SafetyError("Redaction verification could not run fired detectors") from e


def _prepare_recovery(path: Path, original_bytes: bytes) -> Path:
    """Persist the no-backup rollback copy before replacing the original."""
    tmp_path: Path | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".recover",
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as f:
            f.write(original_bytes)
            f.flush()
            os.fsync(f.fileno())
        return tmp_path
    except Exception as e:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise SafetyError(
            "Could not persist recovery copy before redaction; refusing to write"
        ) from e


def _restore_prepared_recovery(path: Path, recovery_path: Path) -> None:
    try:
        os.replace(recovery_path, path)
    except Exception as e:
        raise SafetyError(f"complete recovery copy retained at {recovery_path}") from e


def _restore_from_backup(path: Path, backup_path: Path) -> None:
    try:
        original_bytes = backup_path.read_bytes()
    except Exception as e:
        raise SafetyError(f"backup retained at {backup_path}") from e
    _restore_original(path, original_bytes, backup_path)


def _restore_sidecars_from_backups(
    sidecars: Sequence[Path],
    sidecar_backups: Sequence[Path],
) -> None:
    if len(sidecars) != len(sidecar_backups):
        raise SafetyError("SQLite sidecar recovery state is incomplete")
    for sidecar, sidecar_backup in zip(sidecars, sidecar_backups):
        _restore_from_backup(sidecar, sidecar_backup)


def _restore_prepared_sidecars(
    sidecar_recoveries: Sequence[tuple[Path, Path]],
) -> None:
    for sidecar, recovery_path in sidecar_recoveries:
        _restore_prepared_recovery(sidecar, recovery_path)


def _restore_original(
    path: Path,
    original_bytes: bytes,
    backup_path: Path,
) -> None:
    """Atomically restore backup bytes while retaining recovery evidence."""
    tmp_path: Path | None = None
    complete = False
    try:
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".restore",
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as f:
            f.write(original_bytes)
            f.flush()
            os.fsync(f.fileno())
        complete = True
        os.replace(tmp_path, path)
    except Exception as e:
        if complete and tmp_path is not None and tmp_path.exists():
            evidence = f"complete recovery copy retained at {tmp_path}"
        else:
            evidence = f"backup retained at {backup_path}"
        raise SafetyError(evidence) from e


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
