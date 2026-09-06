"""Round-trip --fix tests for the broad source batch added after v0.1.6,
one per storage family:

- generic single-db SQLite (Warp/Grok CLI/Kiro/Zed share _GenericSqliteSource)
- VS Code fork SQLite state.vscdb (Trae/Void share _VSCodeSqliteSource)
- whole-file JSON (Codebuff/Plandex/Qwen)
- Cline-fork per-task JSON (PearAI)
- line-oriented text (Mentat .log, JetBrains AI .xml) and JSONL (Junie, Grok Build)

Plus a sanity check that every new source is registered with a distinct root.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.pipeline import _redact_all, _scan_file  # noqa: E402
from agentsweep.sources import (  # noqa: E402
    SOURCES,
    CodebuffSource,
    GrokBuildSource,
    GrokCliSource,
    JetBrainsAiSource,
    JunieSource,
    MentatSource,
    PearAiSource,
    PlandexSource,
    QwenCodeSource,
    TraeSource,
    WarpSource,
)

SECRET = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("GROK_HOME", raising=False)


def _scan(source, f: Path):
    _, items, _, _, _ = _scan_file(source, f, ignores=None)
    assert items, f"fixture secret should be detected in {f}"
    return {f: items}


def _ok(source, f: Path):
    rows, errors, _ = _redact_all(source, _scan(source, f), backup=True, force=True)
    assert errors == 0, rows
    assert rows[0][0] == "ok"


def test_generic_sqlite_round_trip(tmp_path: Path) -> None:
    # Warp/Grok/Kiro/Zed all use _GenericSqliteSource — one db, any schema.
    root = tmp_path / "warp"
    root.mkdir()
    db = root / "warp.sqlite"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE agent_conversations (role TEXT, content TEXT)")
    con.execute(
        "INSERT INTO agent_conversations VALUES (?, ?)", ("user", f"my key is {SECRET}")
    )
    con.commit()
    con.close()
    source = WarpSource(root=root)
    assert db in source.files()
    _ok(source, db)
    # secret gone, db still valid
    con = sqlite3.connect(db)
    vals = [r[0] for r in con.execute("SELECT content FROM agent_conversations")]
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    con.close()
    assert all(SECRET not in v for v in vals)


def test_vscode_fork_sqlite_round_trip(tmp_path: Path) -> None:
    # Trae/Void store chat in an ItemTable(value) JSON blob like Cursor.
    root = tmp_path / "Trae" / "User"
    ws = root / "workspaceStorage" / "abc123"
    ws.mkdir(parents=True)
    db = ws / "state.vscdb"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE ItemTable (key TEXT, value TEXT)")
    con.execute(
        "INSERT INTO ItemTable VALUES (?, ?)",
        ("chat", json.dumps({"messages": [{"text": f"use {SECRET}"}]})),
    )
    con.commit()
    con.close()
    source = TraeSource(root=root)
    assert db in source.files()
    _ok(source, db)
    con = sqlite3.connect(db)
    val = con.execute("SELECT value FROM ItemTable").fetchone()[0]
    con.close()
    assert SECRET not in val


def test_codebuff_whole_file_json(tmp_path: Path) -> None:
    root = tmp_path / ".config" / "manicode"
    chat = root / "projects" / "proj" / "chats" / "c1"
    chat.mkdir(parents=True)
    f = chat / "chat-messages.json"
    f.write_text(
        json.dumps([{"role": "user", "content": f"key {SECRET}"}], indent=2),
        encoding="utf-8",
    )
    source = CodebuffSource(root=root)
    assert f in source.files()
    _ok(source, f)
    assert SECRET not in f.read_text(encoding="utf-8")
    json.loads(f.read_text(encoding="utf-8"))


def test_plandex_whole_file_json(tmp_path: Path) -> None:
    root = tmp_path / "plandex-server"
    conv = root / "orgs" / "o1" / "plans" / "p1" / "conversation"
    conv.mkdir(parents=True)
    f = conv / "msg1.json"
    f.write_text(
        json.dumps({"role": "assistant", "message": f"token {SECRET}"}),
        encoding="utf-8",
    )
    source = PlandexSource(root=root)
    assert f in source.files()
    _ok(source, f)
    assert SECRET not in f.read_text(encoding="utf-8")


def test_qwen_checkpoint_json(tmp_path: Path) -> None:
    root = tmp_path / ".qwen"
    d = root / "tmp" / "deadbeef"
    d.mkdir(parents=True)
    f = d / "checkpoint-main.json"
    f.write_text(
        json.dumps([{"role": "user", "parts": [{"text": f"k {SECRET}"}]}]),
        encoding="utf-8",
    )
    source = QwenCodeSource(root=root)
    assert f in source.files()
    _ok(source, f)
    assert SECRET not in f.read_text(encoding="utf-8")


def test_pearai_cline_fork(tmp_path: Path) -> None:
    root = tmp_path / "PearAI"
    task = root / "tasks" / "t1"
    task.mkdir(parents=True)
    f = task / "api_conversation_history.json"
    f.write_text(
        json.dumps(
            [{"role": "user", "content": [{"type": "text", "text": f"s {SECRET}"}]}]
        ),
        encoding="utf-8",
    )
    source = PearAiSource(root=root)
    assert f in source.files()
    _ok(source, f)
    assert SECRET not in f.read_text(encoding="utf-8")


def test_grok_build_jsonl_round_trip(tmp_path: Path) -> None:
    root = tmp_path / ".grok"
    sess = root / "sessions" / "home%2Fproj" / "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    sess.mkdir(parents=True)
    # Credential files sit beside sessions/ and must never be scanned.
    (root / "auth.json").write_text(
        json.dumps({"token": f"secret {SECRET}"}), encoding="utf-8"
    )
    f = sess / "chat_history.jsonl"
    f.write_text(
        json.dumps({"type": "user", "content": f"key {SECRET}"}) + "\n",
        encoding="utf-8",
    )
    (sess / "updates.jsonl").write_text("{}\n", encoding="utf-8")
    source = GrokBuildSource(root=root)
    names = {p.name for p in source.files()}
    assert "chat_history.jsonl" in names
    assert "updates.jsonl" in names
    assert all(p.name != "auth.json" for p in source.files())
    _ok(source, f)
    assert SECRET not in f.read_text(encoding="utf-8")
    json.loads(f.read_text(encoding="utf-8").splitlines()[0])


def test_grok_build_detects_jsonl_layout(tmp_path: Path) -> None:
    root = tmp_path / ".grok"
    root.mkdir()
    (root / "auth.json").write_text("{}", encoding="utf-8")
    # No grok.db — the xAI layout is JSONL under sessions/.
    assert not GrokBuildSource(root=root).is_detected()
    sess = root / "sessions" / "cwd" / "sid"
    sess.mkdir(parents=True)
    (sess / "events.jsonl").write_text("{}\n", encoding="utf-8")
    source = GrokBuildSource(root=root)
    assert source.is_detected()
    assert any(p.name == "events.jsonl" for p in source.files())


def test_grok_cli_missing_db_is_noop(tmp_path: Path) -> None:
    # Grok Build's ~/.grok/sessions JSONL must not make grok-cli crash when
    # grok.db (superagent-ai sqlite) is absent.
    root = tmp_path / ".grok"
    sess = root / "sessions" / "cwd" / "sid"
    sess.mkdir(parents=True)
    (sess / "chat_history.jsonl").write_text(
        json.dumps({"type": "user", "content": f"key {SECRET}"}) + "\n",
        encoding="utf-8",
    )
    source = GrokCliSource(root=root)
    assert source.files() == []
    assert list(source.iter_files()) == []


def test_grok_build_honors_grok_home(tmp_path: Path, monkeypatch) -> None:
    custom = tmp_path / "custom-grok"
    monkeypatch.setenv("GROK_HOME", str(custom))
    assert GrokBuildSource.default_root() == custom


def test_junie_jsonl(tmp_path: Path) -> None:
    root = tmp_path / ".junie"
    sess = root / "sessions"
    sess.mkdir(parents=True)
    f = sess / "s1.jsonl"
    f.write_text(
        json.dumps({"role": "user", "text": f"key {SECRET}"}) + "\n", encoding="utf-8"
    )
    source = JunieSource(root=root)
    assert f in source.files()
    _ok(source, f)
    assert SECRET not in f.read_text(encoding="utf-8")


def test_mentat_log_plaintext(tmp_path: Path) -> None:
    root = tmp_path / ".mentat"
    logs = root / "logs"
    logs.mkdir(parents=True)
    f = logs / "transcript_20260613_120000.log"
    f.write_text(f'{{"role": "user", "text": "my key {SECRET}"}}\n', encoding="utf-8")
    source = MentatSource(root=root)
    assert f in source.files()
    _ok(source, f)
    assert SECRET not in f.read_text(encoding="utf-8")


def test_jetbrains_ai_xml_plaintext(tmp_path: Path) -> None:
    root = tmp_path / "JetBrains"
    ws = root / "IntelliJIdea2026.1" / "workspace"
    ws.mkdir(parents=True)
    f = ws / "deadbeef.xml"
    original = (
        "<application>\n"
        '  <component name="ChatSessionStateTemp">\n'
        f"    <message>use {SECRET} for aws</message>\n"
        "  </component>\n"
        "</application>\n"
    )
    f.write_text(original, encoding="utf-8")
    source = JetBrainsAiSource(root=root)
    assert f in source.files()
    _ok(source, f)
    after = f.read_text(encoding="utf-8")
    assert SECRET not in after
    # line-count preserved (XML structure intact)
    assert len(after.splitlines()) == len(original.splitlines())


def test_all_new_sources_registered_with_distinct_roots() -> None:
    expected = {
        "warp",
        "grok-build",
        "grok-cli",
        "kiro-cli",
        "zed",
        "codebuff",
        "plandex",
        "qwen-code",
        "pearai",
        "trae",
        "void",
        "junie",
        "mentat",
        "jetbrains-ai",
    }
    assert expected <= set(SOURCES)
    # default_root resolves for every registered source without raising,
    # and no two sources share the same root.
    roots = {slug: str(cls().default_root()) for slug, cls in SOURCES.items()}
    # Per-project sources (aider, crush) have no central store — they walk from
    # $HOME for a per-repo artifact, so sharing that root is correct, not a
    # copy-paste slip. The check guards fixed history paths, where a duplicate
    # would mean one source silently scanning another's store.
    home = str(Path.home())
    fixed = {slug: r for slug, r in roots.items() if r != home}
    # grok-cli (sqlite grok.db) and grok-build (sessions/*.jsonl) share
    # ~/.grok but scan different files — not a copy-paste slip.
    grok_shared = {"grok-cli", "grok-build"}
    unique = {slug: r for slug, r in fixed.items() if slug not in grok_shared}
    assert len(set(unique.values())) == len(unique), "sources share a default_root"
    grok_roots = {fixed[slug] for slug in grok_shared}
    assert len(grok_roots) == 1, "grok-cli and grok-build should share ~/.grok"


def test_new_sources_flagged_experimental() -> None:
    experimental = {
        "warp",
        "grok-cli",
        "kiro-cli",
        "zed",
        "codebuff",
        "plandex",
        "qwen-code",
        "pearai",
        "trae",
        "void",
        "junie",
        "mentat",
        "jetbrains-ai",
    }
    for slug in experimental:
        assert SOURCES[slug].experimental, f"{slug} should be experimental"
    # Verified / battle-tested sources must NOT be flagged experimental.
    for slug in (
        "claude-code",
        "cursor",
        "cline",
        "kilo-code",
        "open-interpreter",
        "grok-build",
    ):
        assert not SOURCES[slug].experimental, f"{slug} must stay stable"
