"""SARIF 2.1.0 renderer for GitHub code scanning / CI ingestion."""
from __future__ import annotations

import json

from ..engine import ScanResult
from ..findings import Finding, Severity
from ..rules import all_rules
from ..version import __version__

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule_descriptors() -> list[dict]:
    descriptors = []
    for r in all_rules():
        descriptors.append({
            "id": r.id,
            "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.detail},
            "helpUri": "https://github.com/fevziegeyurtsevenler/uncloak/blob/main/docs/rules.md",
            "help": {"text": f"{r.detail}\n\nRemediation: {r.remediation}"},
            "defaultConfiguration": {"level": _LEVEL[r.severity]},
            "properties": {
                "tags": [r.category, *r.references],
                "security-severity": _SECURITY_SEVERITY[r.severity],
            },
        })
    return descriptors


def render(result: ScanResult, findings: list[Finding]) -> str:
    results = []
    for f in findings:
        region = {"startLine": f.line} if f.line else {"startLine": 1}
        results.append({
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.evidence or f.detail}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": region,
                }
            }],
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "uncloak",
                    "informationUri": "https://github.com/fevziegeyurtsevenler/uncloak",
                    "version": __version__,
                    "rules": _rule_descriptors(),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
