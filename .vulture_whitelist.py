"""Vulture whitelist — known false positives when scanning src/ in isolation.

Run as: vulture src/ .vulture_whitelist.py
Each entry below is a *confirmed* false positive, not a blanket suppression:
see the comment on each line for why vulture can't see the real usage.
Regenerate the shape of this file (not its comments) with:
    vulture src/ --make-whitelist
"""

# argcomplete's completer signature requires **kwargs even when unused.
kwargs  # src/agentsweep/cli.py: source_completer(prefix, **kwargs)

# argcomplete pattern: `some_action.completer = source_completer` is read by
# argcomplete's own internals at shell-completion time, not by our code, so
# vulture can't see the attribute ever being used.
_.completer  # src/agentsweep/cli.py (4 argparse actions wired to source_completer)

# Orphaned marker tuple: kiro-cli is registered (KIRO_CLI_MARKERS, wired to
# KiroCliSource), but this un-suffixed KIRO_MARKERS predates it and isn't
# wired to any source. Left as data, not dead-code-deleted, in case it's
# meant for a future non-CLI Kiro source (see issue #38) rather than a typo.
KIRO_MARKERS  # src/agentsweep/preflight.py

# Only exercised by tests/test_preflight.py, not by any other src/ module.
is_claude_code_running  # src/agentsweep/preflight.py

# Only exercised by tests/test_scan_performance.py and
# tests/test_ported_rules.py respectively — vulture only sees src/ here.
PREFILTER_BACKEND  # src/agentsweep/scanner.py
DETECTOR_IDS  # src/agentsweep/scanner.py

# Engine metadata is an intentionally importable inspection surface for the
# audit command and test subprocesses; their dynamic imports are outside src/.
ENGINE_INVENTORY  # src/agentsweep/scanner.py
EFFECTIVE_ENGINE_MODE  # src/agentsweep/scanner.py

# google-re2 reads this option in its native extension when compiling patterns.
_.log_errors  # src/agentsweep/regex_engine.py

# _LockedProgress in run_all() names its method receiver self_inner (to avoid
# confusion in the nested class); the param is required by the method signature
# but the body forwards to the enclosing progress + lock, so it is never read.
self_inner  # src/agentsweep/pipeline.py

# apply_no_color() sets these on the shared rich Console; rich reads them at
# render time, so vulture can't see the use from src/ alone.
no_color  # src/agentsweep/ui/console.py
_color_system  # src/agentsweep/ui/console.py
