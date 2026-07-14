# Scanner performance notes

Detection runs 189 regexes + a BIP-39 mnemonic check over every string
value in every JSONL line. History sizes are large (900+ files, some with
multi-MB embedded transcripts), so per-byte and per-string costs both matter.

## Landed

- **Keyword pre-filter (≈7.5×).** Each rule carries a required literal
  anchor (`akia`, `ghp_`, `twitter`, …) extracted from its pattern; the
  regex is skipped when the anchor is absent. 180/189 rules are gated.
  Provably lossless (a match always contains its anchor); gated by the
  per-rule fixture tests. See `scanner.py:_prefilter_literals`.
- **Mnemonic gate.** `detect_mnemonics` returns early when a string has
  fewer than 11 word separators — it cannot hold a 12-word phrase — so big
  tokenless blobs (base64, minified JS, long paths) skip tokenization.
- **Single-pass Aho-Corasick anchors.** `pyahocorasick` collapses per-string
  prefilter checks into one O(n) pass (substring fallback if the wheel is
  absent). See `scanner.py:_triggered_indices`.
- **Aider discovery prune.** Default Aider scans no longer `rglob` the
  entire home tree. Junk dirs (`node_modules`, `.git`, `AppData`, …) are
  skipped and depth is capped. See `sources._core._iter_aider_histories`.

## Evaluated and dropped

- **multiprocessing across files.** On Windows `spawn` re-imports modules
  and recompiles all 189 regexes per worker; measured ~1.1× on a 2.4 MB /
  200-file corpus (startup cost dominates), with one run at 0.4×. It also
  risks a re-import fork bomb if an entry point isn't `__main__`-guarded.
  Not worth the risk/complexity for the gain. (Cheap, shared-memory
  goroutines are why the Go tools — gitleaks, trufflehog — parallelize for
  free; Python can't match that without a native engine.)

## Open levers (under research)

- **Native multi-pattern engines** (`google-re2`, `hyperscan`) — large
  speedups but a portability/packaging cost (Windows wheels?).
