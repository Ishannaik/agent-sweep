from __future__ import annotations

import subprocess
import sys


CLAUDE_CODE_MARKERS: tuple[str, ...] = (
    "claude-code",
    "anthropic-ai/claude-code",
    "/claude ",
    # Windows tasklist reports the bare image name ("claude.exe", no path),
    # so the marker must not require a leading backslash.
    "claude.exe",
    "claude.cmd",
    " claude ",
)

CODEX_MARKERS: tuple[str, ...] = (
    "openai/codex",
    "/codex ",
    "codex.exe",
    "codex.cmd",
    " codex ",
)

OPENCODE_MARKERS: tuple[str, ...] = (
    "sst/opencode",
    "/opencode ",
    "opencode.exe",
    "opencode.cmd",
    " opencode ",
)

CURSOR_MARKERS: tuple[str, ...] = (
    "cursor.exe",
    "/cursor ",
    "cursor.cmd",
    " cursor ",
    "anysphere/cursor",
)

WINDSURF_MARKERS: tuple[str, ...] = (
    "Windsurf",
    "windsurf.exe",
    "/windsurf ",
    "windsurf.cmd",
    " windsurf ",
    "codeium/windsurf",
)

AIDER_MARKERS: tuple[str, ...] = (
    "aider",
    "/aider ",
    "aider.exe",
    " aider ",
)

CLINE_MARKERS: tuple[str, ...] = (
    "saoudrizwan.claude-dev",
    "cline",
    "/cline ",
)

GEMINI_CLI_MARKERS: tuple[str, ...] = (
    "gemini",
    "/gemini ",
    "gemini.exe",
    "gemini.cmd",
    " gemini ",
    "google/gemini-cli",
)

CONTINUE_MARKERS: tuple[str, ...] = (
    "continuedev",
    "continue-dev",
    "/continue ",
    "continue.exe",
)

GITHUB_COPILOT_MARKERS: tuple[str, ...] = (
    "GitHub.copilot-chat",
    "copilot-chat",
    "copilot.chat",
)

OPENCLAW_MARKERS: tuple[str, ...] = (
    "openclaw",
    "/openclaw ",
    "openclaw.cmd",
    " openclaw ",
    "openclaw/openclaw",
)

HERMES_MARKERS: tuple[str, ...] = (
    "hermes-agent",
    "/hermes ",
    "hermes.exe",
    "hermes.cmd",
    " hermes ",
    "NousResearch/hermes",
)

GOOSE_MARKERS: tuple[str, ...] = (
    "block/goose",
    "/goose ",
    "goose.exe",
    "goose.cmd",
    " goose ",
)

# Only delimited forms — a bare "llm" substring would match "vllm" and any
# path that happens to contain the letters (llm is a short, common token), so
# the gate keys on the executable / invocation shapes instead.
LLM_MARKERS: tuple[str, ...] = (
    "/llm ",
    "llm.exe",
    "llm.cmd",
    " llm ",
    "datasette/llm",
    "simonw/llm",
)

KILO_CODE_MARKERS: tuple[str, ...] = (
    "kilocode.kilo-code",
    "kilo-code",
    "/kilocode ",
    " kilo ",
)

ROO_CODE_MARKERS: tuple[str, ...] = (
    "rooveterinaryinc.roo-cline",
    "roo-cline",
    "roo-code",
    "/roo ",
)

OPEN_INTERPRETER_MARKERS: tuple[str, ...] = (
    "open-interpreter",
    "open_interpreter",
    "/interpreter ",
    "interpreter.exe",
)

WARP_MARKERS: tuple[str, ...] = (
    "warp-terminal",
    "dev.warp.Warp",
    "/warp ",
    "warp.exe",
)

GROK_CLI_MARKERS: tuple[str, ...] = (
    "superagent-ai/grok-cli",
    "grok-cli",
    "/grok ",
    "grok.cmd",
)

KIRO_CLI_MARKERS: tuple[str, ...] = (
    "kiro-cli",
    "/kiro ",
    "kiro.exe",
)

# No bare "crush": it is an ordinary word that matches unrelated processes
# (crushftp, image-crush), and a false "agent is running" gate blocks redaction.
CRUSH_MARKERS: tuple[str, ...] = (
    "charmbracelet/crush",
    "/crush ",
    "crush.exe",
)

KIRO_MARKERS: tuple[str, ...] = (
    "kiro.kiroagent",
    "kirodotdev",
    "/Kiro ",
)

ZED_MARKERS: tuple[str, ...] = (
    "zed-industries",
    "/zed ",
    "zed.exe",
    " Zed.app",
)

CODEBUFF_MARKERS: tuple[str, ...] = (
    "codebuff",
    "manicode",
    "/codebuff ",
)

PLANDEX_MARKERS: tuple[str, ...] = (
    "plandex",
    "/plandex ",
    "plandex.exe",
    "plandex-server",
)

QWEN_CODE_MARKERS: tuple[str, ...] = (
    "qwen-code",
    "qwenlm/qwen-code",
    "/qwen ",
    "qwen.cmd",
)

PEARAI_MARKERS: tuple[str, ...] = (
    "PearAI.pearai-roo-cline",
    "pearai",
    "/pearai ",
)

TRAE_MARKERS: tuple[str, ...] = (
    "trae-ai",
    "/trae ",
    "Trae.exe",
    " Trae.app",
)

VOID_MARKERS: tuple[str, ...] = (
    "voideditor",
    "void-editor",
    "/void ",
)

JUNIE_MARKERS: tuple[str, ...] = (
    "jetbrains/junie",
    "/junie ",
    "junie.exe",
)

MENTAT_MARKERS: tuple[str, ...] = (
    "abanteai/mentat",
    "/mentat ",
    "mentat.exe",
)

JETBRAINS_AI_MARKERS: tuple[str, ...] = (
    "jetbrains-ai",
    "ai.assistant",
    "ChatSessionStateTemp",
)


def is_agent_running(markers: tuple[str, ...]) -> tuple[bool, str]:
    """Best-effort detection of a running agent process by marker substrings.

    Returns (is_running, matched_marker). If the check itself fails — ps/tasklist
    unavailable, permission denied, etc. — returns (False, "") and the caller
    falls back to the redactor's mtime defense.

    False positives are preferred to false negatives: these are short, common
    strings and we'd rather warn once than silently corrupt a session.
    """
    cmdlines = _list_process_cmdlines()
    if cmdlines is None:
        return (False, "")
    blob = "\n".join(cmdlines).lower()
    for marker in markers:
        if marker in blob:
            return (True, marker.strip())
    return (False, "")


def is_claude_code_running() -> tuple[bool, str]:
    """Back-compat wrapper around is_agent_running for Claude Code."""
    return is_agent_running(CLAUDE_CODE_MARKERS)


def _list_process_cmdlines() -> list[str] | None:
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True,
                timeout=5,
                stderr=subprocess.DEVNULL,
            )
        else:
            out = subprocess.check_output(
                ["ps", "-eo", "args="],
                text=True,
                timeout=5,
                stderr=subprocess.DEVNULL,
            )
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return None
    return out.splitlines()


def is_production_root(source, source_cls) -> bool:
    """Check whether `source` points at the source class's default root."""
    default = source_cls()
    try:
        return source.root.resolve() == default.root.resolve()
    except (OSError, RuntimeError):
        return source.root == default.root
