"""Benchmark harness: repeatable timing for scan hot paths.

Uses pytest-benchmark to provide trend data across commits and catch
gradual drift — a complement to the existing hard-threshold asserts in
test_scan_performance.py, which remain the catastrophic-regression floor.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep import scanner  # noqa: E402
from agentsweep.mnemonic import detect_mnemonics  # noqa: E402
from agentsweep.scanner import _triggered_indices, scan_text  # noqa: E402

# ---------------------------------------------------------------------------
# Hermetic corpus fixture
# ---------------------------------------------------------------------------

# Small (~1 KB): a typical one-shot AI chat with a couple of tokens.
SMALL = (
    "Here is my config file:\n"
    "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "export GITHUB_TOKEN=ghp_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
    "export OPENAI_API_KEY=sk-proj-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c\n"
    "export ANTHROPIC_API_KEY=sk-ant-api03-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5\n"
    "f6a1b2c3d4e5f6a1b2-A\n"
    "export SENTRY_DSN=https://a1b2c3d4e5f6a1b2c3d4@o123456.ingest.sentry.io/789012\n"
    "Also my JWT token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
    "Can you help me debug this error message? The traceback shows a "
    "KeyError on 'DATABASE_URL' — here's my connection string:\n"
    "postgresql://user:P@ssw0rd123@db.example.com:5432/mydb\n"
    "My npm token is npm_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
    "And the Slack webhook is https://hooks.slack.com/"
    "services/T00000000/B00000000/abcdefghijklmnopqrstuvwx\n"
    "Let me also share my .env file for reference:\n"
    "DATABASE_URL=postgresql://admin:secret123@localhost:5432/app\n"
    "REDIS_URL=redis://:redis_pass@localhost:6379/0\n"
    "STRIPE_SECRET_KEY=sk_" "live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d\n"
    "TWILIO_AUTH_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\n"
)

# Medium (~200 KB): a multi-turn AI transcript with repeated patterns
# and realistic token-shaped noise.
_MEDIUM_BASE = (
    "System: You are a helpful coding assistant.\n"
    "User: I need to set up CI/CD with these tokens. Here are the values:\n"
    "export DOCKER_HUB_TOKEN=dckr_pat_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6\n"
    "export DOCKER_HUB_TOKEN=dckr_pat_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6\n"
    "Assessant: Let me help you set up the pipeline. First, let's look at your"
    " configuration.\n"
    "Here's a docker-compose with secrets:\n"
    "version: '3'\nservices:\n  app:\n    environment:\n"
    "      - AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "      - AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    "      - SENDGRID_API_KEY=SG.a1b2c3d4e5f6a1b2c3d4e5.a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5\n"
    "\nNow let me write the deployment script:\n"
    "#!/bin/bash\nset -euo pipefail\n"
    "# Deploy to staging with these env vars set.\n"
    "curl -s -H 'Authorization: Bearer a1b2c3a1b2c3a1b2c3d4' https://api.example.com/deploy\n"
    "echo 'Deploying with config:'\n"
    "cat <<EOF\n"
    "  DATABASE_URL=postgresql://user:pass@host:5432/db\n"
    "  REDIS_URL=redis://user:pass@host:6379/0\n"
    "  SENTRY_DSN=https://key@host/project\n"
    "EOF\n"
    "Here is a sample .env file:\n"
    "GITHUB_TOKEN=ghp_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
    "GITLAB_TOKEN=glpat-a1b2c3d4e5f6a1b2c3d4\n"
    "TWILIO_SID=SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\n"
    "NPM_TOKEN=npm_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
    "PYPI_TOKEN=pypi-AgEIcHlwaS5vcmcA1b2C3d4E5f6A1b2C3d4E5f6A1b2C3d4E5f6A1b2C3d4E5f6\n"
    "HUGGINGFACE_TOKEN=hf_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1\n"
    "OPENAI_API_KEY=sk-proj-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\n"
    "ANTHROPIC_API_KEY=sk-ant-api03-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3-A\n"
    # A JWT and a PEM key block to stress the multi-line scan.
    "JWT_TOKEN=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6\n"
    "Here is a private key:\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAwJLCnkGkGbjZ4JHMoENfkCCgD+PCNMnGSrDQpgTmf/R4dNfn\n"
    "dGpGLuC+BnCC2yF2f7JmRz4OzYv4hCkRkNRBCG8sHuV0Z8HBl2i8cH0GDVkNWr0p\n"
    "XNmH0FZpJk8MFK3jHqL7BdCn0PzYUcSSsGPFVNKH8BK6Jp1dF8K5fIqX1aBjqJeH\n"
    "awIDAQAB\n"
    "-----END RSA PRIVATE KEY-----\n"
    "This key should not be in logs!\n"
    "User: Thanks. Also here's a token=abc123 for my legacy application.\n"
    "import os\ntoken = 'ghp_anothertokenvalue123456789012345678901234'\n"
    "gitlab_token = 'glpat-featureflagtokensoandso'\n"
    "jfrog_token = 'AKCp8k7exampletokenvaluewithcharslong'\n"
    "sendgrid_key = 'SG.xYz789abcdefghijklmnopqr.abcdefghijklmno'\n"
    "stripe_key = 'sk_" "test_abcdefghijklmnopqrstuvwxyz012345'\n"
)
MEDIUM = _MEDIUM_BASE * 30  # ~200 KB

# Large (~1.5 MB): a realistic transcript with many rule hints but few hits,
# plus a noise suffix of non-matching text (hex blob + repeated "curl").
_LARGE_BODY = _MEDIUM_BASE * 30  # ~200 KB of token-rich content
_LARGE_NOISE = (
    "curl -X POST https://api.example.com/data '{\"id\": 12345}'\n" * 500
    + "deadbeef" * 2000
)
LARGE = _LARGE_BODY + _LARGE_NOISE  # ~1.5 MB

# BIP-39 mnemonic stress: wordlist words that don't validate.
# 6250 repetitions of "abandon" — a 50 KB worst case for the windowing
# detector (matches test_mnemonic.py::test_no_quadratic_blowup_on_wordy_text).
MNEMONIC_BLOWUP = ("abandon " * 6250).strip()

BOMB_SCAN_ALL = [
    "a" * 50000,
    "curl " * 10000,
    "token=abc123 " * 4000,
    "https://" + "x/" * 20000,
    "deadbeef" * 8000,
]


# Discovery / small-corpus scans are the hot path that fires on every
# agent-session directory. 3 sizes give a trend line: micro (<1 KB),
# typical session (SMALL), and transcript.
@pytest.mark.benchmark(group="scan_text")
def test_benchmark_scan_text_small(benchmark):
    benchmark(scan_text, SMALL)


@pytest.mark.benchmark(group="scan_text")
def test_benchmark_scan_text_medium(benchmark):
    benchmark(scan_text, MEDIUM)


@pytest.mark.benchmark(group="scan_text")
def test_benchmark_scan_text_large(benchmark):
    benchmark(scan_text, LARGE)


# Prefilter-only: isolate the O(n) anchor dispatch from regex evaluation.
@pytest.mark.benchmark(group="prefilter")
def test_benchmark_prefilter_medium(benchmark):
    lowered = MEDIUM.lower()
    benchmark(_triggered_indices, lowered)


@pytest.mark.benchmark(group="prefilter")
def test_benchmark_prefilter_large(benchmark):
    lowered = LARGE.lower()
    benchmark(_triggered_indices, lowered)


# Mnemonic gate: worst-case wordlist blowup (never validates).
@pytest.mark.benchmark(group="mnemonic")
def test_benchmark_mnemonic_blowup(benchmark):
    benchmark(detect_mnemonics, MNEMONIC_BLOWUP)


# Full-scan of all 5 pathological bombs (the existing test_scan_performance
# floor). This is the closest to "scan the worst inputs" benchmark.
@pytest.mark.benchmark(group="bombs")
def test_benchmark_all_bombs(benchmark):
    def _scan_all():
        for text in BOMB_SCAN_ALL:
            scan_text(text)

    benchmark(_scan_all)
