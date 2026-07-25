"""Hidden / obfuscated text detectors (UC1xx).

These find content that a human reviewer cannot see but the model reads:
invisible Unicode code points, bidi tricks, variation-selector data channels,
confusable homoglyphs and encoded instruction blobs.

The invisible-text detectors are the core of uncloak: the whole premise is that
you cannot trust your eyes when reviewing an agent extension.
"""
from __future__ import annotations

import base64
import binascii
import re

from .. import rules
from ..findings import Finding, Severity

# --- code point sets --------------------------------------------------------
TAG_LO, TAG_HI = 0xE0000, 0xE007F
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x180E, 0x200E, 0x200F}
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def _in_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _line_of(text: str, index: int) -> int:
    """1-indexed line number of a character offset."""
    return text.count("\n", 0, index) + 1


def decode_tags(text: str) -> str:
    """Decode Unicode Tags-block characters back to their ASCII payload."""
    return "".join(chr(ord(c) - TAG_LO) for c in text if TAG_LO <= ord(c) <= TAG_HI)


def _first_index(text: str, predicate) -> int:
    for i, c in enumerate(text):
        if predicate(ord(c)):
            return i
    return -1


# --- individual detectors ---------------------------------------------------
def _tags(text: str, path: str) -> list[Finding]:
    hits = [c for c in text if TAG_LO <= ord(c) <= TAG_HI]
    if not hits:
        return []
    decoded = decode_tags(text).strip()
    idx = _first_index(text, lambda cp: TAG_LO <= cp <= TAG_HI)
    ev = f"{len(hits)} tag chars -> decoded: {decoded!r}" if decoded else f"{len(hits)} tag chars"
    return [rules.finding("UC101", path, line=_line_of(text, idx), evidence=ev[:400])]


def _zero_width(text: str, path: str) -> list[Finding]:
    hits = [c for c in text if ord(c) in ZERO_WIDTH]
    if not hits:
        return []
    idx = _first_index(text, lambda cp: cp in ZERO_WIDTH)
    names = ", ".join(sorted({f"U+{ord(c):04X}" for c in hits}))
    return [rules.finding("UC102", path, line=_line_of(text, idx),
                          evidence=f"{len(hits)} zero-width chars ({names})")]


def _bidi(text: str, path: str) -> list[Finding]:
    hits = [c for c in text if ord(c) in BIDI]
    if not hits:
        return []
    idx = _first_index(text, lambda cp: cp in BIDI)
    names = ", ".join(sorted({f"U+{ord(c):04X}" for c in hits}))
    return [rules.finding("UC103", path, line=_line_of(text, idx),
                          evidence=f"{len(hits)} bidi control chars ({names})")]


def _variation_selectors(text: str, path: str) -> list[Finding]:
    hits = [c for c in text if _in_variation_selector(ord(c))]
    # A single VS on an emoji is legitimate; a run of them is a data channel.
    if len(hits) < 4:
        return []
    idx = _first_index(text, lambda cp: _in_variation_selector(cp))
    return [rules.finding("UC104", path, line=_line_of(text, idx),
                          evidence=f"{len(hits)} variation selectors (possible encoded byte stream)")]


# Confusable letters that are frequently abused (non-Latin look-alikes).
_LATIN = re.compile(r"[A-Za-z]")
_CYRILLIC = re.compile(r"[Ѐ-ӿ]")
_GREEK = re.compile(r"[Ͱ-Ͽ]")
_WORD = re.compile(r"[^\s\W]{2,}", re.UNICODE)


def _homoglyphs(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for m in _WORD.finditer(text):
        token = m.group(0)
        scripts = 0
        if _LATIN.search(token):
            scripts += 1
        if _CYRILLIC.search(token):
            scripts += 1
        if _GREEK.search(token):
            scripts += 1
        if scripts >= 2 and token not in seen:
            seen.add(token)
            out.append(rules.finding("UC105", path, line=_line_of(text, m.start()),
                                     evidence=f"mixed-script token: {token!r}"))
        if len(out) >= 5:  # cap noise
            break
    return out


_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){20,}")
_ENCODED_INTENT = re.compile(
    r"curl|wget|bash|/bin/sh|http[s]?://|ignore|secret|api[_-]?key|token|password|exfil|\.env|ssh",
    re.IGNORECASE,
)


def _try_decode(blob: str) -> str:
    for decoder in (
        lambda b: base64.b64decode(b + "=" * (-len(b) % 4), validate=False),
        lambda b: binascii.unhexlify(b) if len(b) % 2 == 0 else b"",
    ):
        try:
            raw = decoder(blob)
        except (binascii.Error, ValueError):
            continue
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(c.isprintable() or c in "\n\t" for c in s)
        if s and printable / max(len(s), 1) > 0.85:
            return s
    return ""


def _encoded_blobs(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []
    for regex in (_B64_RUN, _HEX_RUN):
        for m in regex.finditer(text):
            decoded = _try_decode(m.group(0))
            if decoded and _ENCODED_INTENT.search(decoded):
                out.append(rules.finding(
                    "UC107", path, line=_line_of(text, m.start()),
                    evidence=f"encoded blob decodes to: {decoded.strip()[:120]!r}"))
            if len(out) >= 3:
                return out
    return out


def scan(text: str, path: str) -> list[Finding]:
    """Run all hidden-text detectors over ``text``."""
    findings: list[Finding] = []
    for fn in (_tags, _zero_width, _bidi, _variation_selectors, _homoglyphs, _encoded_blobs):
        findings.extend(fn(text, path))
    return findings


def visible_and_hidden(text: str) -> str:
    """Return visible text plus any decoded hidden payload.

    Intent detectors run over this so that instructions hidden inside a
    Tags-block payload are analysed too, not just what a human can read.
    """
    hidden_payload = decode_tags(text)
    return text if not hidden_payload else f"{text}\n{hidden_payload}"
