# Scanner performance notes

Detection runs 205 regexes + a BIP-39 mnemonic check over every string
value in every JSONL line. History sizes are large (900+ files, some with
multi-MB embedded transcripts), so per-byte and per-string costs both matter.

## Landed

- **Keyword pre-filter (approx 7.5x).** Each rule carries a required literal
  anchor (`akia`, `ghp_`, `twitter`, ...) extracted from its pattern; the
  regex is skipped when the anchor is absent. 199/205 rules are gated.
  Provably lossless (a match always contains its anchor); gated by the
  per-rule fixture tests. See `scanner.py:_prefilter_literals`.
- **Mnemonic gate.** `detect_mnemonics` returns early when a string has
  fewer than 11 word separators -- it cannot hold a 12-word phrase -- so big
  tokenless blobs (base64, minified JS, long paths) skip tokenization.
- **Single-pass Aho-Corasick anchors.** `pyahocorasick` collapses per-string
  prefilter checks into one O(n) pass (substring fallback if the wheel is
  absent). See `scanner.py:_triggered_indices`.
- **Optional mixed RE2 engine.** `pip install 'agentsweep[fast]'` enables
  `google-re2` for the rules it can compile; the current registry selects 144
  RE2 rules and keeps 58 Python-`re` fallbacks with explicit audit reasons.
  Missing wheels leave the default install fully functional on stdlib. Python
  `re` remains the semantic oracle for non-ASCII Unicode-sensitive rules, for
  short strings, and for a rule with more than four matches, where the RE2
  Python wrapper is measurably slower. The backend selection itself is static
  at import time. See [RE2 compatibility](RE2_COMPATIBILITY.md) and
  [benchmark results](RE2_BENCHMARK_RESULTS.md).
- **Aider discovery prune.** Default Aider scans no longer `rglob` the
  entire home tree. Junk dirs (`node_modules`, `.git`, `AppData`, ...) are
  skipped and depth is capped. See `sources._core._iter_aider_histories`.
- **Cross-source parallelism for scan --all.** Phase 1 (discovery) and
  Phase 2 (scanning) in `run_all()` now run all selected sources
  concurrently via `ThreadPoolExecutor` instead of sequentially. Each source
  is fully independent (separate root, separate files, separate ignore set)
  so there is no shared mutable state between workers. Source-level
  concurrency is capped at 4 workers; combined with each source's own
  inner file-level pool (up to 8 workers) the total thread count stays
  bounded at ~32. Rich's Live progress display is protected by a
  `threading.Lock` so it is never updated from two threads simultaneously.
  Results are re-ordered by original index after all futures complete, so
  findings output remains deterministic regardless of which source finishes
  first. See `pipeline.py:run_all`.


## Evaluated and dropped

- **multiprocessing across files.** On Windows `spawn` re-imports modules
  and recompiles all 205 regexes per worker; measured ~1.1× on a 2.4 MB /
  200-file corpus (startup cost dominates), with one run at 0.4×. It also
  risks a re-import fork bomb if an entry point isn't `__main__`-guarded.
  Not worth the risk/complexity for the gain. (Cheap, shared-memory
  goroutines are why the Go tools — gitleaks, trufflehog — parallelize for
  free; Python can't match that without a native engine.)

## Open levers (under research)

- **Hyperscan and other native multi-pattern engines.** They may offer more
  speed, but add a larger portability and packaging burden than the optional
  RE2 path.
