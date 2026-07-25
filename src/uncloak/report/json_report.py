"""Machine-readable JSON renderer."""
from __future__ import annotations  # noqa: F404

import json

from ..engine import ScanResult
from ..findings import Finding
from ..version import __version__


def render(result: ScanResult, findings: list[Finding]) -> str:
    payload = {
        "tool": "uncloak",
        "version": __version__,
        "target": result.root,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "summary": result.counts(),
        "worst_severity": result.worst().label,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
