# Issue #90 experiment log

All corpora and tokens used below are synthetic. No user history, VPN data, or
other application data is read by these experiments.
Raw JSON outputs named below are generated locally and intentionally excluded
from Git.

## Environment

- Date: 2026-08-06 (Asia/Shanghai)
- Baseline commit: `9ce11ef8331f6a7021dfb06bf8f046fa426fbbf6`
- Machine: MacBook Air (Apple M3, 8 CPU cores: 4 performance + 4 efficiency)
- Memory: 16 GiB unified memory; macOS 26.5.2; native `arm64` CPython 3.13.11
- Power: AC connected, battery charging; Low Power Mode disabled
- Disk available before experiments: 207 GiB
- Python environment: `pyahocorasick 2.3.1`, `pytest-benchmark 5.2.3`
- Optional engine: `google-re2 1.1.20251105`
- Rule registry: 202 regex rules plus 1 function-based mnemonic detector
- Prefilter backend: Aho-Corasick

## E00 — no-RE2 baseline

- Hypothesis: the current stdlib-only scanner is a correct control before any
  optional-engine change.
- Engine: `auto` with `google-re2` absent (effective stdlib).
- Correctness command: `uv run pytest tests/ -q`
- Result: 664 passed in 9.25 s.
- Retained as the pre-change correctness baseline.

## E01 — RE2 compatibility probe

- Hypothesis: syntax compilation alone is insufficient for safe replacement.
- Method: compile every current rule with `google-re2 1.1.20251105`, with RE2
  error logging disabled, then compare RE2 and Python `re` Unicode boundaries.
- Result: 144/202 patterns compile; 58 reject lookaround or `\\Z`. RE2's
  ASCII `\\b`, `\\w`, `\\d`, and `\\s` differ from Python `re`'s default
  Unicode semantics (for example, a token adjacent to a Chinese character).
- Decision: use RE2 only after compile success, with exact stdlib guards for
  Unicode-sensitive inputs; retain stdlib fallback with an explicit reason for
  every syntax-incompatible rule.

## E02 — conservative mixed registry (dropped)

- Hypothesis: merely substituting every syntax-compatible pattern produces a
  useful file-level gain.
- Change: initial registry selected only 81 rules whose Unicode semantics were
  trivially safe; 121 rules stayed on stdlib.
- Corpus: 16 MiB `few_large_strings`, SHA-256
  `201c2b63a84bb667aa7260cfe07cf2aaf453eda3c9c2738400514eecceb03df3`.
- Result: the 3-trial quick matrix gained only 4.0–9.9%; the 95% interval at
  one worker crossed zero. Local output: `e02_quick_few_large.json`.
- Diagnosis: `google-re2` encoded a Python string once per rule invocation;
  the spaced corpus also spent most time in BIP-39 tokenization.
- Decision: dropped this conservative selection as insufficient.

## E03 — shared ASCII bytes and guarded Unicode selection (retained)

- Hypothesis: one scanner-owned ASCII byte buffer removes per-pattern RE2
  encoding, while non-ASCII text can retain exact stdlib semantics.
- Change: scanner passes shared bytes only for ASCII; 63 Unicode-sensitive
  rules use stdlib for non-ASCII inputs and `\b` candidates are verified where
  needed. Selection rose to 144 RE2 and 58 syntax fallbacks.
- Correctness: parity, Unicode/NUL/newline, 10,000 fixed-seed differential,
  source integration, and 30-repeat worker tests passed.
- Result: CPU-heavy 16 MiB formal matrix was strongly positive. Local output:
  `e03_cpu_heavy_16m.json`.
- Decision: retained, then tested realistic workloads separately.

## E04–E07 — realistic workload calibration

- E04 used a repeated-token realistic payload. A 16 MiB, 4-worker probe was
  only +5.0%, because it produced 19,344 findings and measured construction
  more than normal history scanning. This failed the 10% realistic goal.
- E05 changed the profile to sparse findings, but prose remained BIP-39-heavy.
  Formal 16 MiB result at eight workers: +6.45%, CI [+6.25%, +6.94%]. Raw:
  `e05_realistic_16m.json`.
- E06 reused the scanner's existing ASCII lowercase text in the BIP-39 walker;
  mnemonic and parity tests passed, but this alone did not establish the
  realistic threshold.
- E07 revised `realistic_mixed` v2 to 60% prose/log and 40% compact structured
  tool/config payloads, with sparse compatible and fallback findings. Formal
  result was +20.88%, CI [+20.49%, +21.20%]. Raw:
  `e07_realistic_16m.json`.
- Decision: retained the semantic profile change because it adds the source
  shapes required by the goal; E04/E05 remain recorded failures.

## E08–E12 — regression discovery (first runtime strategy dropped)

- Formal 16 MiB checks preserved raw results for benign, many-small,
  hit-heavy, anchor-heavy, and adversarial inputs.
- Result: benign, anchor-heavy, and adversarial improved, but all-RE2 bytes
  execution regressed many-small by 30.52% and hit-heavy by 28.29%.
- Local outputs: `e08_benign_16m_w8.json`, `e09_many_small_16m_w8.json`,
  `e10_hit_heavy_16m_w8.json`, `e11_anchor_heavy_16m_w8.json`, and
  `e12_adversarial_16m_w8.json`.
- Profile evidence: RE2's Python match objects add per-result overhead; short
  strings also pay wrapper setup cost. The initial 64-match dense guard was
  itself too expensive and was dropped.

## E13–E21 — bounded runtime execution guards (retained)

- Hypothesis: retain static per-rule RE2 selection, but use exact stdlib
  iteration for strings below 512 characters or after the fifth match for one
  rule. This avoids documented wrapper pathologies without changing any
  accepted match.
- Change: `RE2_MIN_INPUT_CHARS=512`; `RE2_MAX_MATCHES=4`; a dense rule
  re-scans from the beginning with its existing compiled stdlib pattern.
- Correctness: dedicated long-ASCII RE2 dispatch and dense-restart tests,
  plus all parity tests, passed.
- Final 16 MiB local outputs: CPU-heavy `e15_cpu_heavy_16m_final.json`,
  realistic `e16_realistic_16m_final.json`, and regression
  `e17_benign_16m_final.json` through `e21_adversarial_16m_final.json`.
- Result: many-small −0.52%, hit-heavy −1.94%, benign +4.89%, anchor-heavy
  +4.18%, and adversarial +3.43%; all satisfy the no-regression limits.

## E22–E24 — same-process soak and memory control

- Hypothesis: repeated mixed-engine scans do not produce RE2-specific leaks,
  crashes, deadlocks, or finding drift.
- Method: 16 MiB realistic corpus, 8 workers, production file path, per-round
  finding hash and current/peak RSS.
- Result: 30-round auto and stdlib controls had identical findings; both
  showed allocator warm-up. The clean-checkout 90-round auto run rose 45.4 MiB
  through round 60, then only 0.8 MiB net in its final 30 rounds; wall-time
  first and final deciles were stable. Local outputs: `e22_auto_realistic_30.json`,
  `e23_stdlib_realistic_30.json`, and `e24_auto_realistic_90.json`.
- Decision: retained; documented as a scaled 90-round soak, not a 30–60 minute
  claim.

## E25–E26 — standard 512 MiB confirmation

- Method: clean commit `821607645479573281281e4336e02ba9ebae4c40`, maximum
  effective worker count (8), 2 warmups + 9 interleaved measured child
  processes, unchanged swap usage, and full raw execution order with seeds
  20260825 and 20260826.
- CPU-heavy: 512 MiB, 632 files, zero findings, SHA-256
  `e58f0333fc5d069eee0d3b7eecae1083b9cc80079294f16998a778ecda3ebb2d`.
  Auto +185.33%, CI [+184.97%, +185.99%]. Local output:
  `e25_cpu_heavy_512m_final.json`.
- Realistic: 512 MiB, 128 files, 9,909 findings (6,606 compatible / 3,303
  fallback), SHA-256
  `9c4719e5ebf9c3ede0f16650356c71853a814a6fba5dba35216023ab3e8e7663`.
  Auto +21.75%, CI [+16.90%, +23.72%]. Local output:
  `e26_realistic_512m_final.json`.
- Decision: both required performance gates are met. Full tables and
  reproduction commands are in [RE2 benchmark results](docs/RE2_BENCHMARK_RESULTS.md).

## E27 — forced-stdlib main-branch regression control

- Hypothesis: adapter dispatch must not materially slow a user who forces the
  stdlib engine (or cannot install the optional extra).
- Method: a temporary clean snapshot of baseline `9ce11ef` and the current
  branch both ran `CodexSource.files → pipeline._scan_all` against the same
  16 MiB CPU-heavy synthetic corpus with eight workers. After two warmups per
  version, nine child-process samples per version were interleaved in a fixed
  order.
- Result: baseline median 1.9114 s; current forced-stdlib median 1.9138 s;
  current relative change −0.13%. Both runs scanned 40 strings, returned zero
  findings, and matched finding hash `4f53cda…02b945`.
- Local output: `e27_stdlib_main_baseline_16m.json`.
- Decision: retained; the control is within the required 3% stdlib bound.
