"""Intent detectors (UC2xx/3xx/4xx and UC106).

Pattern-based detection of dangerous *intent* in the combined visible + decoded
hidden text: prompt-injection primitives, stealth, credential/exfil, shell/RCE
and hidden markup. Each pattern maps to exactly one catalog rule.

Detectors report the first occurrence per rule per file to keep output readable;
the engine aggregates across detectors.
"""
from __future__ import annotations

import re
from typing import Optional

from .. import rules
from ..findings import Finding

_FLAGS = re.IGNORECASE | re.DOTALL

# (rule_id, pattern). Order does not matter; one finding max per rule per file.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("UC201", re.compile(
        r"(?:ignore|disregard|forget|override)\s+(?:all\s+|the\s+|any\s+|your\s+)*"
        r"(?:previous|prior|above|earlier|preceding|system|initial)\s+"
        r"(?:instruction|prompt|context|rule|direction)", _FLAGS)),
    ("UC202", re.compile(
        r"you\s+are\s+now\b|act\s+as\s+(?:an?\s+)?(?:dan|unrestricted|jailbroken|evil)"
        r"|do\s+anything\s+now|developer\s+mode|\bDAN\b|jailbreak", _FLAGS)),
    ("UC203", re.compile(
        r"do\s*n['o]?t\s+(?:mention|tell|inform|reveal|notify|alert|show)\b[^\n]{0,40}\buser"
        r"|without\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?user"
        r"|without\s+the\s+user['’]?s?\s+(?:knowledge|awareness|consent)"
        r"|keep\s+(?:this|it)\s+(?:secret|hidden|between\s+us)"
        r"|secretly\s+(?:send|copy|read|forward|exfiltrate|post|upload)"
        r"|silently\s+(?:send|copy|read|forward|exfiltrate|post|upload)", _FLAGS)),
    ("UC205", re.compile(
        r"if\s+(?:the\s+)?user\s+(?:asks|says|mentions|requests|types)\b[^\n]{0,60}"
        r"(?:then\s+)?(?:secretly|silently|also|quietly|additionally)"
        r"|when(?:ever)?\b[^\n]{0,40}\bthen\s+secretly", _FLAGS)),
    ("UC301", re.compile(
        r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token"
        r"|private[_-]?key|aws[_-]?secret|client[_-]?secret|password|passwd|credential)\b", _FLAGS)),
    ("UC302", re.compile(
        r"\.env\b|/\.ssh/|\bid_rsa\b|/\.aws/|\.aws/credentials|/etc/passwd|\.netrc\b"
        r"|\.git-credentials|/\.config/gcloud|login\s*data|cookies\.sqlite|keychain", _FLAGS)),
    ("UC303", re.compile(
        r"https?://[^\s'\"]*(?:webhook|/hook|collect|exfil|beacon|pastebin|paste\.ee"
        r"|requestbin|pipedream|ngrok|burpcollaborator|interact\.sh|oast\.|dnslog|termbin)"
        r"|https?://\d{1,3}(?:\.\d{1,3}){3}\b", _FLAGS)),
    ("UC304", re.compile(
        r"\b(?:nslookup|dig|host)\b[^\n]{0,40}\$\(?"
        r"|[a-z0-9.-]+\.(?:dnslog|oast|interact|burpcollaborator)\.[a-z]{2,}", _FLAGS)),
    ("UC401", re.compile(
        r"\|\s*(?:bash|sh|zsh)\b|\b(?:bash|sh|zsh)\s+-c\b|os\.system\s*\("
        r"|subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True|child_process|\.exec(?:Sync)?\s*\(", _FLAGS)),
    ("UC402", re.compile(
        r"(?:curl|wget)\s+[^\n|]*\|\s*(?:bash|sh|python)"
        r"|(?:curl|wget)\b[^\n]*&&[^\n]*(?:bash|sh|python)"
        r"|Invoke-Expression|(?:^|\W)iex\s*\(|IEX\s*\(", _FLAGS)),
    ("UC403", re.compile(
        r"(?:run|execute|invoke|çalıştır)\b[^\n]{0,50}[\w./-]+\.(?:sh|py|ps1|js|rb)\b", _FLAGS)),
    ("UC404", re.compile(
        r"pip\s+install\s+(?:git\+|https?://)|npm\s+install\s+https?://"
        r"|curl[^\n]*\|\s*(?:python|node)|iwr[^\n]*iex", _FLAGS)),
    ("UC106", re.compile(
        r"<!--(?:(?!-->).)*?(?:ignore|secret|do\s+not\s+tell|instruction|system\s+prompt"
        r"|api[_-]?key|password)(?:(?!-->).)*?-->"
        r"|style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0"
        r"|width\s*:\s*0|color\s*:\s*#?fff)", _FLAGS)),
]


def find(text: str, rule_ids: set[str]) -> list[tuple[str, "re.Match"]]:
    """Return ``(rule_id, match)`` for the given rules that match ``text``.

    Used by the MCP target parser to run a focused subset of patterns against
    structured fields (tool descriptions, server commands).
    """
    out: list[tuple[str, re.Match]] = []
    for rule_id, pattern in _PATTERNS:
        if rule_id in rule_ids:
            m = pattern.search(text)
            if m:
                out.append((rule_id, m))
    return out


def _snippet(text: str, start: int, end: int, limit: int = 100) -> str:
    frag = text[start:end]
    frag = re.sub(r"\s+", " ", frag).strip()
    return frag[:limit] + ("…" if len(frag) > limit else "")


def scan(text: str, path: str, visible_len: Optional[int] = None) -> list[Finding]:
    """Scan combined visible+hidden ``text`` for dangerous intent.

    ``visible_len`` is the length of the human-visible portion; matches beyond it
    are inside a decoded hidden payload and are labelled as such.
    """
    findings: list[Finding] = []
    for rule_id, pattern in _PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        in_hidden = visible_len is not None and m.start() >= visible_len
        line = None if in_hidden else text.count("\n", 0, m.start()) + 1
        prefix = "[hidden payload] " if in_hidden else ""
        findings.append(rules.finding(
            rule_id, path, line=line, evidence=prefix + _snippet(text, m.start(), m.end())))
    return findings
