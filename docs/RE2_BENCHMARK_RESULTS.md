# Optional RE2 benchmark results

All inputs were generated synthetic JSONL. No agent history, application data,
or real credentials were used. Raw samples, execution order, environment
snapshots, corpus hashes, and finding hashes are reproducible local output and
are intentionally excluded from Git.

## Environment and method

- MacBook Air, Apple M3 (4 performance + 4 efficiency cores), 16 GiB unified
  memory; macOS 26.5.2; native arm64 CPython 3.13.11.
- AC power; Low Power Mode off. `google-re2` 1.1.20251105,
  `pyahocorasick` 2.3.1, and `pytest-benchmark` 5.2.3.
- Each benchmark uses the production path `CodexSource.files → iter_strings →
  pipeline._scan_all`, with Aho-Corasick, BIP-39, finding construction, and
  overlap dedupe enabled.
- `stdlib` forces all 202 regex rules through Python `re`. `auto` selected
  144 RE2 rules and 58 syntax fallbacks on this machine. Every child verifies
  the stdlib-generated finding count and SHA-256 before it is accepted.
- Formal matrices use isolated child processes, two warmups and nine measured
  trials per configuration. Configurations are randomly interleaved with a
  fixed seed; no best-result selection is used.
- Median child-process startup was 49.7 ms (`stdlib`) versus 61.9 ms (`auto`)
  on CPU-heavy input, and 48.9 ms versus 61.2 ms on realistic input: a
  roughly 12 ms RE2 import/registry cost, within the 100 ms target. The default
  no-RE2 path was separately tested as a full fallback.
- Raw JSON output and generated corpora are intentionally excluded from Git;
  the commands below recreate them locally.
- The standard 512 MiB and soak runs were regenerated from clean commit
  `821607645479573281281e4336e02ba9ebae4c40`; every environment snapshot
  records `git_dirty: false`. Earlier E02–E21 development-stage runs reported
  `git_dirty: true`, not exact checkout identifiers.

These measurements describe this machine and dependency set, not all CPUs or
operating systems.

## Standard 512 MiB evidence

Both standard corpora use seed 42; execution-order seeds are 20260825 and
20260826. Swap usage was unchanged before and after each formal matrix
(258.50 MiB used); the machine remained on AC with Low Power Mode disabled.

| Corpus | Engine | Workers | Median s | MiB/s | CPU | Peak RSS | Finding hash |
|---|---|---:|---:|---:|---:|---:|---|
| CPU-heavy `few_large_strings` | stdlib | 8 | 60.50 | 8.47 | 100.5% | 136.1 MiB | `4f53cda…02b945` |
| CPU-heavy `few_large_strings` | auto | 8 | 21.21 | 24.16 | 171.7% | 175.5 MiB | `4f53cda…02b945` |
| realistic mixed | stdlib | 8 | 107.87 | 4.75 | 100.6% | 236.4 MiB | `b071756…0bd789` |
| realistic mixed | auto | 8 | 88.60 | 5.78 | 111.7% | 242.8 MiB | `b071756…0bd789` |

- CPU-heavy improvement: **+185.33%**, bootstrap 95% CI **[+184.97%,
  +185.99%]**. Corpus SHA-256:
  `e58f0333fc5d069eee0d3b7eecae1083b9cc80079294f16998a778ecda3ebb2d`.
- Realistic mixed improvement: **+21.75%**, bootstrap 95% CI **[+16.90%,
  +23.72%]**. Its 9,909 findings include 6,606 RE2-compatible and 3,303
  fallback-rule findings. Corpus SHA-256:
  `9c4719e5ebf9c3ede0f16650356c71853a814a6fba5dba35216023ab3e8e7663`.

Local `execution_order` output retains every warmup and measured sample for
thermal review; both runs use the exact execution seed.

## Quick worker scaling

The 16 MiB CPU-heavy matrix supplies the worker curve while the 512 MiB run
above supplies the standard-size evidence.

| Engine | 1 worker median | 2 workers | 4 workers | 8 workers | 8/1 speedup |
|---|---:|---:|---:|---:|---:|
| stdlib | 1.906 s | 1.908 s | 1.910 s | 1.913 s | 1.00× |
| auto | 1.074 s | 0.839 s | 0.717 s | 0.690 s | 1.56× |

At eight workers, auto is +177.07% over stdlib (95% CI
[+175.66%, +179.15%]) and reaches 165.8% median process CPU utilization,
versus stdlib's 100.4%.
That is 19.5% parallel efficiency for auto at eight workers, versus 12.5% for
stdlib. The remaining work is Python-side JSON traversal, BIP-39, finding
construction/deduplication, and the intentionally retained fallback rules.
E15 and the E27 forced-stdlib control use the same generator-v1 corpus. Their
within-record comparisons remain valid, but their absolute seconds should not
be compared with the generator-v2 standard artifacts above.

## Regression checks (16 MiB, 8 workers)

| Corpus | stdlib median s | auto median s | Auto change | 95% CI | Result |
|---|---:|---:|---:|---|---|
| benign low-hit | 1.738 | 1.657 | +4.89% | [+4.28%, +5.31%] | passes 5% limit |
| many small strings | 1.398 | 1.406 | −0.52% | [−0.72%, +0.09%] | passes 8% limit |
| hit-heavy | 2.134 | 2.176 | −1.94% | [−2.20%, −1.42%] | passes 8% limit |
| anchor-heavy, no hit | 6.118 | 5.872 | +4.18% | [+3.64%, +4.48%] | improved |
| adversarial | 10.416 | 10.071 | +3.43% | [+3.22%, +3.71%] | improved |

Every measured sample has a single stable finding hash; local JSON output
retains the individual samples.

The forced-stdlib control was also compared directly with the pre-Issue-90
`main` commit on the same 16 MiB CPU corpus: 2 warmups and 9 interleaved trials
per version gave 1.9114 s for `main` and 1.9138 s for current forced stdlib,
or **−0.13%** (well inside the 3% regression bound). Both produced zero
findings and the same hash; local output retains all samples.

## Soak check

`auto`, 8 workers, and the 16 MiB realistic corpus completed 90 consecutive
same-process scans with the same finding hash (`effb132e…ce265b8`), 312
findings, zero truncated files, no crash, and no deadlock. Median wall time
was 2.745 s; the first and final ten-round means were 2.769 s and 2.725 s.

RSS rose during allocator warm-up (64.1 MiB to 109.5 MiB by round 60), then
only 0.8 MiB net across the final 30 rounds (ending at 110.2 MiB; 0.6 MiB
range). A 30-round stdlib control showed the same behavior and a larger initial
rise (61.3 MiB to 97.8 MiB).
Local soak output retains the per-round records.
This is a scaled 90-round check, not a claim of a 30–60 minute soak.

## Reproduce

```bash
uv sync --extra dev --extra fast

uv run python scripts/generate_stress_corpus.py \
  --profile realistic_mixed --size-mib 512 --output "$TMPDIR/agentsweep-realistic"
uv run python scripts/benchmark_regex_engines.py \
  --corpus "$TMPDIR/agentsweep-realistic" --workers 8 --warmups 2 --trials 9 \
  --seed 20260826 --output "$TMPDIR/agentsweep-benchmark.json"

AGENTSWEEP_REGEX_ENGINE=auto uv run python scripts/run_re2_soak.py \
  --corpus "$TMPDIR/agentsweep-realistic" --workers 8 --rounds 30 \
  --output "$TMPDIR/agentsweep-soak.json"
```

Use a writable, empty output directory; the scripts refuse to overwrite a
corpus or result file. Generated corpora and raw results are intentionally not
committed.

A fresh archive of this commit was also installed with `uv sync --extra dev
--extra fast` on CPython 3.12: the 37 mixed-engine contract tests passed, and
both deptry and vulture were clean.
