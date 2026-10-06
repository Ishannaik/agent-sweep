"""Format-specific helpers: SQLite copy-and-redact, JSONL, JSON, plaintext,
plus discovery for agents that store history beside each project."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Callable, Iterator

from ..redactor import SafetyError, jsonl_lines
from ._base import KeyPath, _line_ending, _set_by_path, _walk_json


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------


def _quote_ident(name: str) -> str:
    """Quote a SQLite identifier (table/column name) per the SQL standard.

    Table/column names here are never user-supplied query input -- they come
    either from a fixed Python-literal whitelist or from introspecting the
    very same file being redacted (sqlite_master / PRAGMA table_info). But an
    identifier can itself legally contain a double quote (SQLite lets you
    CREATE TABLE "foo""bar"), so bare f-string interpolation isn't safe
    against a maliciously-crafted db file. Doubling embedded quotes and
    wrapping in "..." is SQLite's own escaping rule for identifiers.
    """
    return '"' + name.replace('"', '""') + '"'


def sqlite_sidecars(db: Path) -> list[Path]:
    """The `-wal` / `-shm` files SQLite keeps beside `db`, if they exist.

    `_redact_sqlite_copy` folds the WAL into the copy it returns, so once
    that copy replaces `db` these two are both stale and — in the `-wal`'s
    case — still full of the plaintext we just redacted.
    """
    return [p for p in (Path(f"{db}-wal"), Path(f"{db}-shm")) if p.is_file()]


def _sqlite_verification_identities(
    path: Path,
    entries: list[tuple[int, KeyPath, str]],
    columns_fn,
    target_keypaths: frozenset[tuple[object, ...]],
) -> list[object]:
    """Batch stable identities for verification after SQLite VACUUM.

    Physical rowids are not stable across VACUUM. Identities therefore use
    the table, rewritten column, nested JSON path, and the row's metadata
    excluding every column targeted in this transaction. An empty metadata
    tuple is safe for a singleton logical location; redactor.py rejects any
    resulting duplicate identity.
    """
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as e:
        raise SafetyError("Cannot open SQLite source for redaction verification") from e
    try:
        allowed = set(columns_fn(con))
        targeted_columns: dict[str, set[str]] = {}
        for target_keypath in target_keypaths:
            if (
                len(target_keypath) < 3
                or not isinstance(target_keypath[0], str)
                or not isinstance(target_keypath[2], str)
                or (target_keypath[0], target_keypath[2]) not in allowed
            ):
                raise SafetyError(
                    "SQLite redaction target has an unverifiable location"
                )
            targeted_columns.setdefault(target_keypath[0], set()).add(target_keypath[2])

        grouped: dict[str, list[tuple[int, KeyPath, str]]] = {}
        for entry in entries:
            _line, keypath, _value = entry
            if (
                len(keypath) < 3
                or not isinstance(keypath[0], str)
                or not isinstance(keypath[1], int)
                or not isinstance(keypath[2], str)
                or (keypath[0], keypath[2]) not in allowed
            ):
                raise SafetyError(
                    "SQLite source yielded an unverifiable redaction location"
                )
            grouped.setdefault(keypath[0], []).append(entry)

        identities_by_location: dict[tuple[int, tuple[object, ...]], object] = {}
        for table, table_entries in grouped.items():
            quoted_table = _quote_ident(table)
            columns = [
                row[1] for row in con.execute(f"PRAGMA table_info({quoted_table})")
            ]
            immutable = [
                column
                for column in columns
                if column not in targeted_columns.get(table, set())
            ]
            select_columns = ", ".join(_quote_ident(column) for column in immutable)
            rows: dict[int, tuple[object, ...]] = {}
            rowids = sorted({entry[1][1] for entry in table_entries})
            for start in range(0, len(rowids), 900):
                chunk = rowids[start : start + 900]
                placeholders = ", ".join("?" for _ in chunk)
                query = (
                    f"SELECT rowid{', ' if select_columns else ''}{select_columns} "  # nosec B608 # Identifiers quoted; values bound below.
                    f"FROM {quoted_table} WHERE rowid IN ({placeholders})"
                )
                rows.update(
                    {row[0]: tuple(row[1:]) for row in con.execute(query, chunk)}
                )
            for line, keypath, _value in table_entries:
                row = rows.get(keypath[1])
                if row is None:
                    raise SafetyError("SQLite source lost a row before verification")
                immutable_state = tuple(
                    (column, _sqlite_identity_value(value))
                    for column, value in zip(immutable, row)
                )
                location = (line, tuple(keypath))
                if location in identities_by_location:
                    raise SafetyError(
                        "SQLite source yielded duplicate redaction locations"
                    )
                identities_by_location[location] = (
                    "sqlite",
                    table,
                    keypath[2],
                    tuple(keypath[3:]),
                    immutable_state,
                )
        return [
            identities_by_location[(line, tuple(keypath))]
            for line, keypath, _value in entries
        ]
    except sqlite3.Error as e:
        raise SafetyError("Cannot read SQLite row identities for verification") from e
    finally:
        con.close()


def _sqlite_identity_value(value) -> tuple[str, object]:
    if isinstance(value, (str, int, float, bytes)) or value is None:
        return (type(value).__name__, value)
    raise SafetyError("SQLite row has an unsupported immutable identity value")


def _redact_sqlite_copy(path: Path, redactions: list, columns_fn) -> bytes:
    """Apply SQLite redactions to a temp copy of `path` and return its bytes.

    The production database is never touched here — the pipeline writes the
    returned bytes back through redactor.safe_write, which owns the .bak
    backup, the atomic replace and the audit record (the same contract as
    text sources). Steps:

      1. Snapshot `path` into a sibling tempfile via sqlite's backup API
         (page-consistent, checkpoints any WAL into the copy).
      2. Run the UPDATEs against the copy with secure_delete on, then
         VACUUM, so the replaced plaintext cannot survive in freelist or
         page slack space.
      3. Gate on PRAGMA integrity_check before returning the copy's bytes.

    `columns_fn(con)` returns the source's whitelisted (table, column)
    pairs; redactions targeting anything outside that whitelist are skipped.
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".redact"
    )
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        try:
            src_con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error as e:
            raise SafetyError(f"Cannot open {path} read-only: {e}") from e
        try:
            dst_con = sqlite3.connect(str(tmp))
            try:
                src_con.backup(dst_con)
                dst_con.execute("PRAGMA secure_delete = ON")
                allowed = set(columns_fn(dst_con))
                _apply_sqlite_updates(dst_con, redactions, allowed)
                dst_con.commit()
                # FTS5 external-content indexes keep their own tokenized (and
                # case-folded) copy of the text. The sync triggers only write a
                # 'delete' marker on UPDATE, so the old term stays physically
                # present in a live segment page that VACUUM can't reach. Merge
                # the segments first, which applies the deletes and drops the
                # freed content — then secure_delete + VACUUM scrub the pages.
                _fts5_optimize(dst_con)
                dst_con.commit()
                dst_con.execute("VACUUM")
                row = dst_con.execute("PRAGMA integrity_check").fetchone()
                if row is None or row[0] != "ok":
                    raise SafetyError(
                        f"Redacted copy of {path.name} failed "
                        f"integrity_check; refusing to write"
                    )
            finally:
                dst_con.close()
        finally:
            src_con.close()
        return tmp.read_bytes()
    except sqlite3.Error as e:
        raise SafetyError(f"SQLite error while redacting {path.name}: {e}") from e
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _fts5_optimize(con: sqlite3.Connection) -> None:
    """Run the FTS5 'optimize' command on every FTS5 index in the database.

    An external-content FTS5 table is synced by triggers that, on UPDATE,
    only insert a 'delete' marker — the redacted term survives, case-folded,
    in a live segment page. 'optimize' merges all segments into one, applying
    those deletes so the term physically leaves the index. Generic (keys off
    sqlite_master) so any FTS5-bearing source is covered, not just llm. The
    fts5vocab virtual tables are excluded — they carry no content and don't
    accept 'optimize'."""
    rows = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND lower(sql) LIKE '%using fts5%' "
        "AND lower(sql) NOT LIKE '%using fts5vocab%'"
    ).fetchall()
    for (name,) in rows:
        q = _quote_ident(name)
        con.execute(f"INSERT INTO {q}({q}) VALUES ('optimize')")  # nosec B608 # q is SQL-escaped via _quote_ident(), not raw interpolation; bandit can't see through the helper


def _apply_sqlite_updates(
    con: sqlite3.Connection,
    redactions: list,
    allowed: set[tuple[str, str]],
) -> None:
    """Run redaction UPDATEs on `con`. Keypath encoding per SQLite row:
    [table, rowid, column] (+ JSON sub-path when the column holds JSON)."""
    for _line_num, kp, new_val in redactions:
        if len(kp) < 3:
            continue
        table, rowid, col = kp[0], kp[1], kp[2]
        if (table, col) not in allowed:
            continue
        q_table, q_col = _quote_ident(table), _quote_ident(col)
        sub_kp = kp[3:]
        if not sub_kp:
            con.execute(
                f"UPDATE {q_table} SET {q_col} = ? WHERE rowid = ?",  # nosec B608 # q_table/q_col are SQL-escaped via _quote_ident(), not raw interpolation; bandit can't see through the helper
                (new_val, rowid),
            )
        else:
            cur = con.execute(
                f"SELECT {q_col} FROM {q_table} WHERE rowid = ?",  # nosec B608 # q_table/q_col are SQL-escaped via _quote_ident(), not raw interpolation; bandit can't see through the helper
                (rowid,),
            )
            row = cur.fetchone()
            if row is None:
                continue
            try:
                obj = json.loads(row[0])
            except (json.JSONDecodeError, TypeError):
                continue
            _set_by_path(obj, sub_kp, new_val)
            con.execute(
                f"UPDATE {q_table} SET {q_col} = ? WHERE rowid = ?",  # nosec B608 # q_table/q_col are SQL-escaped via _quote_ident(), not raw interpolation; bandit can't see through the helper
                (json.dumps(obj, ensure_ascii=False), rowid),
            )


# ---------------------------------------------------------------------------
# Format helpers (JSONL, whole-file JSON, plaintext)
# ---------------------------------------------------------------------------


def _iter_jsonl_strings(path: Path) -> Iterator[tuple[int, KeyPath, str]]:
    """Yield (line_num, keypath, value) for every string in a JSONL file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    for i, line in enumerate(jsonl_lines(text), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        yield from _walk_json(obj, [], i)


def _apply_jsonl_redactions(
    path: Path,
    redactions: list[tuple[int, KeyPath, str]],
) -> str:
    """Apply redactions to a JSONL file, preserving line count and endings."""
    text = path.read_bytes().decode("utf-8")
    lines = jsonl_lines(text)
    by_line: dict[int, list[tuple[KeyPath, str]]] = {}
    for line_num, kp, new_val in redactions:
        by_line.setdefault(line_num, []).append((kp, new_val))
    out: list[str] = []
    for i, line in enumerate(lines, 1):
        if i not in by_line or not line.strip():
            out.append(line)
            continue
        ending = _line_ending(line)
        body = line[: len(line) - len(ending)]
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            out.append(line)
            continue
        for kp, new_val in by_line[i]:
            _set_by_path(obj, kp, new_val)
        out.append(json.dumps(obj, ensure_ascii=False) + ending)
    return "".join(out)


# Whole-file JSON is json.loads'd entirely into memory before scanning, so a
# multi-GB document (e.g. a Kiro IDE session) would OOM before the pipeline's
# per-file scan budget could help. Skip documents above this size.
_MAX_JSON_FILE_BYTES = 100_000_000


def _iter_json_file_strings(path: Path) -> Iterator[tuple[int, KeyPath, str]]:
    """Yield all string values from a whole-file JSON object/array."""
    try:
        if path.stat().st_size > _MAX_JSON_FILE_BYTES:
            return
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return
    yield from _walk_json(obj, [], 1)


def _apply_json_file_redactions(
    path: Path,
    redactions: list[tuple[int, KeyPath, str]],
) -> str:
    """Apply redactions to a whole-file JSON document, returning str.

    The pipeline writes the result with fmt="json", so safe_write
    independently re-validates it as one JSON document. Read or parse
    failures raise SafetyError: by redaction time the file has already
    scanned as valid JSON, so anything else is a race or corruption —
    fail closed rather than silently writing empty or unredacted content.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise SafetyError(f"Cannot re-read {path.name} for redaction: {e}") from e
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise SafetyError(
            f"{path.name} is no longer valid JSON; refusing to redact"
        ) from e
    for _line_num, kp, new_val in redactions:
        _set_by_path(obj, kp, new_val)
    out = json.dumps(obj, ensure_ascii=False, indent=2)
    if text.endswith("\n"):
        out += "\n"
    return out


def _iter_plaintext_lines(path: Path) -> Iterator[tuple[int, KeyPath, str]]:
    """Yield (line_num, [line_num], line_text) for every non-empty line."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip():
            yield (i, [i], line)


# ---------------------------------------------------------------------------
# Per-project discovery (agents that keep history beside each project rather
# than in one central directory: Aider, Crush)
# ---------------------------------------------------------------------------

# Vendor / VCS / build-cache dirs — never a project root, so they are pruned at
# ANY depth. A directory with one of these names holds tooling, not a project
# the user ran an agent in, so dropping it can't hide a real history.
_PROJECT_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cache",
        ".npm",
        ".yarn",
        ".pnpm-store",
        ".cargo",
        ".rustup",
    }
)

# OS-profile trees (caches, not project roots) — pruned ONLY when they sit
# directly under $HOME. Unlike the vendor set, these are ordinary words a real
# project directory can legitimately be named ("Library", "AppData", "Trash"),
# so pruning them at any depth silently dropped real histories — a secret
# scanner reporting a false all-clear. `.config` is deliberately NOT here:
# people keep git-tracked dotfiles (e.g. ~/.config/nvim) there and run agents in
# them, so it must be walked; the depth cap + vendor set above bound the cost.
# ponytail: home-top-only prune, not per-name cache-child pruning. If ~/.config
# on some box (large browser profiles) makes a scan slow, add the specific
# cache-child dir names — don't re-blanket-prune .config and lose real repos.
_PROJECT_SKIP_DIRS_HOME_TOP: frozenset[str] = frozenset(
    {
        "AppData",
        "Library",
        ".Trash",
        "Trash",
        ".local",
    }
)


def _iter_project_histories(
    root: Path,
    *,
    find: Callable[[Path, list[str], list[str]], Iterator[Path]],
    max_depth: int,
    source_label: str,
    artifact_desc: str,
    warn: bool = False,
) -> Iterator[Path]:
    """Yield history artifacts under root with junk dirs pruned.

    `find` receives each walked (dirpath, dirnames, filenames) and yields the
    artifacts it recognises there, so a source can match a file at a project
    root (Aider) or a file inside a data dir (Crush).

    Vendor/cache dirs are pruned at any depth; OS-profile dirs only when they
    sit directly under $HOME (so a project named "Library" or a dotfiles repo
    under ~/.config is still scanned). Descent stops at `max_depth`; when that
    happens and `warn` is True (the scan path, not detection), a one-line stderr
    warning naming `source_label`/`artifact_desc` is emitted so the cap is never
    silent — a scanner that quietly skips files hides live secrets.
    """
    if not root.exists():
        return
    root = root.resolve()
    home = Path.home().resolve()
    capped = 0

    def _onerror(_err: OSError) -> None:
        # Permission / reparse-point noise under $HOME is expected. Skip and
        # keep walking the rest of the tree.
        return

    # os.walk so we can mutate dirs in place and skip huge subtrees.
    for dirpath, dirnames, filenames in os.walk(
        root,
        topdown=True,
        onerror=_onerror,
    ):
        # Depth relative to root (root itself is depth 0). ``resolved`` is
        # reused for the home-top check, so there's no extra resolve() per dir.
        try:
            resolved = Path(dirpath).resolve()
            rel = resolved.relative_to(root)
            depth = 0 if str(rel) == "." else len(rel.parts)
        except ValueError:
            # Walked outside root (symlink / mount edge case). Stop descending.
            dirnames.clear()
            continue
        if depth >= max_depth:
            if dirnames:
                capped += 1
            dirnames.clear()
        else:
            at_home_top = resolved == home
            dirnames[:] = [
                d
                for d in dirnames
                if d not in _PROJECT_SKIP_DIRS
                and not (at_home_top and d in _PROJECT_SKIP_DIRS_HOME_TOP)
            ]
        yield from find(Path(dirpath), dirnames, filenames)

    if warn and capped:
        print(
            f"warning: {source_label} discovery reached the depth cap "
            f"({max_depth}) in {capped} "
            f"director{'y' if capped == 1 else 'ies'}; any "
            f"{artifact_desc} nested deeper was not scanned — "
            f"pass --root <path> to reach it",
            file=sys.stderr,
        )


def _apply_plaintext_redactions(
    path: Path,
    redactions: list[tuple[int, KeyPath, str]],
) -> str:
    """Apply line-level redactions to a plain-text file, returning str.

    The pipeline writes the result with fmt="text", so safe_write enforces
    that the line count is unchanged (redaction replaces whole lines 1:1).
    Read failures raise SafetyError — fail closed rather than silently
    writing empty content.
    """
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise SafetyError(f"Cannot re-read {path.name} for redaction: {e}") from e
    lines = text.splitlines(keepends=True)
    by_line: dict[int, str] = {ln: nv for ln, _kp, nv in redactions}
    out: list[str] = []
    for i, line in enumerate(lines, 1):
        if i in by_line:
            ending = _line_ending(line)
            out.append(by_line[i] + ending)
        else:
            out.append(line)
    return "".join(out)
