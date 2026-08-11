"""Crypto wallet seed-phrase detection (BIP-39 + Electrum).

A mnemonic is 12/15/18/21/24 words from the fixed BIP-39 wordlist — the
format behind essentially every major chain's wallets (BTC, ETH, SOL,
BNB, ADA, DOGE, LTC, DOT, AVAX, TRX, ...). Wordlist membership alone
would false-positive on English prose, so a candidate window only counts
if its BIP-39 checksum verifies or Electrum's HMAC seed-version tag
matches — cryptographic validation, not pattern matching.

Monero uses its own 1626-word list (25 words) and is not covered yet.
"""
from __future__ import annotations

import hashlib
import hmac
import re

from .bip39_words import WORDS

_WORDSET = frozenset(WORDS)
_INDEX = {w: i for i, w in enumerate(WORDS)}

# Longest first: a valid 24-word phrase contains wordlist-valid 12-word
# windows; claiming the longest stops double-reporting.
_LENGTHS = (24, 21, 18, 15, 12)

# Electrum v2 seed-version prefixes: standard, segwit, 2FA, 2FA-segwit.
_ELECTRUM_PREFIXES = ("01", "100", "101", "102")

_TOKEN = re.compile(r"[a-zA-Z]{3,8}")
_GAP = re.compile(r"[ \t\r\n,;.]*\Z")
_MAX_GAP = 3  # chars between words: tighter than prose, loose enough for \r\n


def _bip39_checksum_ok(words: list[str]) -> bool:
    n = len(words)
    cs_bits = n // 3            # 12->4 ... 24->8
    ent_bits = 32 * cs_bits     # 128 ... 256
    acc = 0
    for w in words:
        acc = (acc << 11) | _INDEX[w]
    checksum = acc & ((1 << cs_bits) - 1)
    entropy = (acc >> cs_bits).to_bytes(ent_bits // 8, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    return checksum == expected


def _electrum_version_ok(words: list[str]) -> bool:
    tag = hmac.new(b"Seed version", " ".join(words).encode("utf-8"),
                   hashlib.sha512).hexdigest()
    return tag.startswith(_ELECTRUM_PREFIXES)


def _valid(words: list[str]) -> bool:
    return _bip39_checksum_ok(words) or _electrum_version_ok(words)


def detect_mnemonics(text: str, ascii_lowered: str | None = None):
    """Yield scanner.Finding objects for validated seed phrases in `text`."""
    # Cheap reject before tokenizing: a 12-word phrase needs at least 11
    # word separators. A big tokenless blob (base64, minified JS, a long
    # path) has far fewer, so skip it without the per-token regex scan.
    # Lossless: any string holding 12 separated words has >= 11 separators.
    if (text.count(" ") + text.count("\n")
            + text.count(",") + text.count(";")) < 11:
        return []

    from .scanner import Finding  # late import: scanner imports this module

    # The scanner already lowercases ASCII text for its regex prefilter. Reuse
    # that same-length text here instead of allocating one lowercase word per
    # token. Non-ASCII stays on the original path so source spans are exact.
    token_text = ascii_lowered if ascii_lowered is not None else text
    already_lowered = ascii_lowered is not None

    # Group word tokens into runs where every word is on the wordlist and
    # words are separated only by short whitespace/punctuation gaps.
    runs: list[list[tuple[str, int, int]]] = []
    current: list[tuple[str, int, int]] = []
    last_end = None
    for m in _TOKEN.finditer(token_text):
        word = m.group()
        if not already_lowered:
            word = word.lower()
        gap_ok = (last_end is None
                  or (m.start() - last_end <= _MAX_GAP
                      and _GAP.match(text, last_end, m.start())))
        if word in _WORDSET and (gap_ok or not current):
            if not gap_ok:
                runs.append(current)
                current = []
            current.append((word, m.start(), m.end()))
        else:
            if current:
                runs.append(current)
            current = []
        last_end = m.end()
    if current:
        runs.append(current)

    findings = []
    for run in runs:
        i = 0
        while i < len(run):
            claimed = False
            for length in _LENGTHS:
                if i + length > len(run):
                    continue
                window = run[i:i + length]
                if _valid([w for w, _, _ in window]):
                    start = window[0][1]
                    end = window[-1][2]
                    words = [w for w, _, _ in window]
                    findings.append(Finding(
                        rule="bip39-mnemonic",
                        display="Crypto seed phrase (BIP-39/Electrum)",
                        value=text[start:end],
                        masked=f"{words[0]} …[{length} words]… {words[-1]}",
                        span=(start, end),
                    ))
                    i += length
                    claimed = True
                    break
            if not claimed:
                i += 1
    return findings
