# Optional RE2 benchmark results

All inputs were generated synthetic JSONL. No agent history, application data,
or real credentials were used. Raw samples, execution order, environment
snapshots, corpus hashes, and finding hashes are committed under
[`artifacts/benchmarks`](../artifacts/benchmarks/).

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

These measurements describe this machine and dependency set, not all CPUs or
operating systems.

## Standard 512 MiB evidence

Both standard corpora use seed 42. Swap usage was unchanged before and after
each formal matrix (266.50 MiB used); the machine remained on AC with Low
Power Mode disabled.

| Corpus | Engine | Workers | Median s | MiB/s | CPU | Peak RSS | Finding hash |
|---|---|---:|---:|---:|---:|---:|---|
| CPU-heavy `few_large_strings` | stdlib | 8 | 60.47 | 8.47 | 100.5% | 136.9 MiB | `4f53cda…02b945` |
| CPU-heavy `few_large_strings` | auto | 8 | 21.23 | 24.13 | 171.5% | 172.6 MiB | `4f53cda…02b945` |
| realistic mixed | stdlib | 8 | 104.71 | 4.89 | 100.6% | 232.7 MiB | `b071756…0bd789` |
| realistic mixed | auto | 8 | 87.11 | 5.88 | 113.0% | 243.8 MiB | `b071756…0bd789` |

- CPU-heavy improvement: **+184.86%**, bootstrap 95% CI **[+184.25%,
  +185.25%]**. Corpus SHA-256:
  `e58f0333fc5d069eee0d3b7eecae1083b9cc80079294f16998a778ecda3ebb2d`.
  See [`e25_cpu_heavy_512m_final.json`](../artifacts/benchmarks/e25_cpu_heavy_512m_final.json).
- Realistic mixed improvement: **+20.21%**, bootstrap 95% CI **[+20.00%,
  +20.42%]**. Its 9,909 findings include 6,606 RE2-compatible and 3,303
  fallback-rule findings. Corpus SHA-256:
  `9c4719e5ebf9c3ede0f16650356c71853a814a6fba5dba35216023ab3e8e7663`.
  See [`e26_realistic_512m_final.json`](../artifacts/benchmarks/e26_realistic_512m_final.json).

Measured samples are effectively flat in both standard artifacts. The
CPU-heavy auto warmup includes one expected cold 22.82 s sample before its
21.2 s steady state; the raw `execution_order` fields retain it for thermal
review.

## Quick worker scaling

The 16 MiB CPU-heavy matrix supplies the worker curve while the 512 MiB run
above supplies the standard-size evidence.

| Engine | 1 worker median | 2 workers | 4 workers | 8 workers | 8/1 speedup |
|---|---:|---:|---:|---:|---:|
| stdlib | 1.906 s | 1.908 s | 1.910 s | 1.913 s | 1.00× |
| auto | 1.074 s | 0.839 s | 0.717 s | 0.690 s | 1.56× |

At eight workers, auto is +177.07% over stdlib (95% CI
[+175.66%, +179.15%]) and reaches 165.8% median process CPU utilization,
versus stdlib's 100.4%. See
[`e15_cpu_heavy_16m_final.json`](../artifacts/benchmarks/e15_cpu_heavy_16m_final.json).

## Regression checks (16 MiB, 8 workers)

| Corpus | stdlib median s | auto median s | Auto change | 95% CI | Result |
|---|---:|---:|---:|---|---|
| benign low-hit | 1.738 | 1.657 | +4.89% | [+4.28%, +5.31%] | passes 5% limit |
| many small strings | 1.398 | 1.406 | −0.52% | [−0.72%, +0.09%] | passes 8% limit |
| hit-heavy | 2.134 | 2.176 | −1.94% | [−2.20%, −1.42%] | passes 8% limit |
| anchor-heavy, no hit | 6.118 | 5.872 | +4.18% | [+3.64%, +4.48%] | improved |
| adversarial | 10.416 | 10.071 | +3.43% | [+3.22%, +3.71%] | improved |

Every measured sample has a single stable finding hash. The raw files are
[`e17_benign_16m_final.json`](../artifacts/benchmarks/e17_benign_16m_final.json),
[`e18_many_small_16m_final.json`](../artifacts/benchmarks/e18_many_small_16m_final.json),
[`e19_hit_heavy_16m_final.json`](../artifacts/benchmarks/e19_hit_heavy_16m_final.json),
[`e20_anchor_heavy_16m_final.json`](../artifacts/benchmarks/e20_anchor_heavy_16m_final.json),
and [`e21_adversarial_16m_final.json`](../artifacts/benchmarks/e21_adversarial_16m_final.json).

## Soak check

`auto`, 8 workers, and the 16 MiB realistic corpus completed 90 consecutive
same-process scans with the same finding hash (`effb132e…ce265b8`), 312
findings, zero truncated files, no crash, and no deadlock. Median wall time
was 2.728 s; the first and final ten-round means were 2.727 s and 2.732 s.

RSS rose during allocator warm-up (63.8 MiB to 106.9 MiB by round 60), then
only about 3 MiB across the final 30 rounds (ending at 106.9 MiB). A 30-round
stdlib control showed the same behavior and a larger initial rise (36.6 MiB).
The raw records are [`e24_auto_realistic_90.json`](../artifacts/soak/e24_auto_realistic_90.json)
and [`e23_stdlib_realistic_30.json`](../artifacts/soak/e23_stdlib_realistic_30.json).
This is a scaled 90-round check, not a claim of a 30–60 minute soak.

## Reproduce

```bash
uv sync --extra dev --extra fast

uv run python scripts/generate_stress_corpus.py \
  --profile realistic_mixed --size-mib 512 --output "$TMPDIR/agentsweep-realistic"
uv run python scripts/benchmark_regex_engines.py \
  --corpus "$TMPDIR/agentsweep-realistic" --workers 8 --warmups 2 --trials 9 \
  --seed 20260826 --output artifacts/benchmarks/local-realistic.json

AGENTSWEEP_REGEX_ENGINE=auto uv run python scripts/run_re2_soak.py \
  --corpus "$TMPDIR/agentsweep-realistic" --workers 8 --rounds 30 \
  --output artifacts/soak/local-auto.json
```

Use a writable, empty output directory; the scripts refuse to overwrite a
corpus or result file. Generated corpora are intentionally not committed.
