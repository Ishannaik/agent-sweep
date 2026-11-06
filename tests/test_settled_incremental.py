"""Generic incremental selection and settled redaction regression fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import pipeline, preflight, redactor  # noqa: E402
from agentsweep.cli import main  # noqa: E402

KEY = "AKIA" + "IOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTSWEEP_NO_UPDATE", "1")
    monkeypatch.setattr(preflight, "_list_process_cmdlines", lambda: [])


def history(tmp_path):
    root = tmp_path / "codex"
    root.mkdir()
    old, fresh = root / "old.jsonl", root / "fresh.jsonl"
    for path in (old, fresh):
        path.write_text(json.dumps({"content": KEY}) + "\n", encoding="utf-8")
    age = time.time() - 7200
    os.utime(old, (age, age))
    return root, old, fresh


def run(verb, root, *args):
    return main([verb, "--source", "codex", "--root", str(root), *args])


def test_newer_than_selects_recent_history(tmp_path, capsys):
    root, old, fresh = history(tmp_path)
    assert run("scan", root, "--json", "--newer-than", "600") == 1
    assert {f["file"] for f in json.loads(capsys.readouterr().out)} == {str(fresh)}


def test_files_from_only_narrows_discovered_history(tmp_path, capsys):
    root, old, fresh = history(tmp_path)
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps({"content": KEY}) + "\n")
    listing = tmp_path / "files.txt"
    listing.write_text(f"{old}\n{outside}\n")
    assert run("scan", root, "--json", "--files-from", str(listing)) == 1
    assert {f["file"] for f in json.loads(capsys.readouterr().out)} == {str(old)}


def test_settled_defers_fresh_and_open_files(tmp_path, monkeypatch):
    root, old, fresh = history(tmp_path)
    monkeypatch.setattr(pipeline, "open_paths", lambda: {str(old)})
    monkeypatch.setattr(pipeline, "is_open_now", lambda p: False)
    assert run("fix", root, "--no-backup", "--settled", "60") == 0
    assert KEY in old.read_text() and KEY in fresh.read_text()


def test_settled_fails_closed_without_lsof(tmp_path, monkeypatch):
    root, old, fresh = history(tmp_path)
    monkeypatch.setattr(pipeline, "open_paths", lambda: None)
    assert run("fix", root, "--no-backup", "--settled", "60") == 0
    assert KEY in old.read_text()


def test_settled_preserves_inode_and_mtime(tmp_path, monkeypatch):
    root, old, fresh = history(tmp_path)
    before = old.stat()
    monkeypatch.setattr(pipeline, "open_paths", lambda: {"/unrelated"})
    monkeypatch.setattr(pipeline, "is_open_now", lambda p: False)
    assert run("fix", root, "--no-backup", "--settled", "60") == 0
    assert KEY not in old.read_text() and KEY in fresh.read_text()
    assert (old.stat().st_ino, old.stat().st_mtime_ns) == (
        before.st_ino,
        before.st_mtime_ns,
    )


def test_settled_defers_changed_version_after_scan(tmp_path, monkeypatch):
    root, old, fresh = history(tmp_path)
    monkeypatch.setattr(pipeline, "open_paths", lambda: {"/unrelated"})
    monkeypatch.setattr(pipeline, "is_open_now", lambda p: False)
    real = redactor.safe_write

    def append_before_write(path, *args, **kwargs):
        if path == old:
            with path.open("a") as stream:
                stream.write(json.dumps({"content": "late output"}) + "\n")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(pipeline, "safe_write", append_before_write)
    assert run("fix", root, "--no-backup", "--settled", "60") == 0
    assert KEY in old.read_text() and "late output" in old.read_text()


def test_settled_defers_changed_identity_before_redaction(tmp_path, monkeypatch):
    root, old, fresh = history(tmp_path)
    monkeypatch.setattr(pipeline, "open_paths", lambda: {"/unrelated"})
    monkeypatch.setattr(pipeline, "is_open_now", lambda p: False)
    real = pipeline._build_redactions
    changed = False

    def change_once(items, template):
        nonlocal changed
        if not changed:
            changed = True
            old.write_text(
                json.dumps({"content": "late output"}) + "\n" + old.read_text()
            )
        return real(items, template)

    monkeypatch.setattr(pipeline, "_build_redactions", change_once)
    assert run("fix", root, "--no-backup", "--settled", "60") == 0
    assert changed and KEY in old.read_text()


def test_guard_copy_kept_when_restore_fails(tmp_path, monkeypatch):
    target = tmp_path / "x.jsonl"
    original = b'{"a": 1}\n'
    target.write_bytes(original)
    real_open = open

    class Failing:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self):
            return self.stream.read()

        def seek(self, *args):
            return self.stream.seek(*args)

        def write(self, data):
            raise OSError("disk full")

        def truncate(self):
            return self.stream.truncate()

        def flush(self):
            return self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    def fake_open(path, mode="r", *args, **kwargs):
        stream = real_open(path, mode, *args, **kwargs)
        return Failing(stream) if str(path) == str(target) and mode == "r+b" else stream

    monkeypatch.setattr("builtins.open", fake_open)
    with pytest.raises(OSError):
        redactor._write_in_place(
            target, original, hashlib.sha256(original).hexdigest(), b'{"a": 2}\n'
        )
    assert [p.read_bytes() for p in tmp_path.glob(".x.jsonl.*.guard")] == [original]
