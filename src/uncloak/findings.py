"""Core data model: severities and findings.

A ``Finding`` is a single detected issue tied to a rule in the catalog. The
engine produces a list of findings per scanned file; reporters render them.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(enum.IntEnum):
    """Ordered severities. Higher value = worse. Used for thresholds/exit codes."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    """One detected issue.

    Attributes
    ----------
    rule_id:    Stable catalog id, e.g. ``UC101``.
    title:      Human-readable rule title.
    severity:   Severity of this occurrence.
    path:       File the finding was located in (repo-relative when possible).
    line:       1-indexed line number, or ``None`` when not line-bound.
    evidence:   Short snippet or decoded payload proving the finding.
    detail:     One-line explanation of why this is risky.
    category:   Grouping bucket (see ``rules.Category``).
    references: External framework references (OWASP LLM, MITRE ATLAS, CWE).
    remediation:What the author/reviewer should do about it.
    """

    rule_id: str
    title: str
    severity: Severity
    path: str
    line: Optional[int] = None
    evidence: str = ""
    detail: str = ""
    category: str = ""
    references: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "detail": self.detail,
            "category": self.category,
            "references": list(self.references),
            "remediation": self.remediation,
        }
