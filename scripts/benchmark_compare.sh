#!/usr/bin/env bash
# Run benchmarks and compare against saved baselines.
#
# On the first run (no baseline), succeeds without comparison.
# On subsequent runs, fails if any benchmark regresses by >= threshold.
#
# Usage:
#   scripts/benchmark_compare.sh           # defaults to 10% threshold
#   BENCHMARK_FAIL_THRESHOLD=5 scripts/benchmark_compare.sh
#
# CI integration (GitHub Actions):
#   - Restore .benchmarks/ from cache before running (key on main).
#   - Run this script.
#   - Save .benchmarks/ to cache after running (main branch only).
set -euo pipefail

THRESHOLD="${BENCHMARK_FAIL_THRESHOLD:-10}"

echo "=== Benchmark regression guard (threshold: ${THRESHOLD}%) ==="

if [ -d .benchmarks ] && [ -n "$(find .benchmarks -type f -name '*.json' 2>/dev/null)" ]; then
    echo "Baseline data found — comparing against previous run."
else
    echo "No baseline data found — saving current results as initial baseline."
fi

python -m pytest tests/test_benchmarks.py \
    --benchmark-only \
    --benchmark-autosave \
    --benchmark-compare \
    --benchmark-compare-fail="min:${THRESHOLD}%" \
    --benchmark-group-by=func
