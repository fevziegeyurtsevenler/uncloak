"""Scan orchestration.

``scan_path`` walks a file or directory, reads text files, classifies each,
runs the detectors and aggregates a :class:`ScanResult`. The lethal-trifecta
detector runs once over all findings, treating the target as a single extension.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .detectors import hidden, intent, trifecta
from .findings import Finding, Severity
from . import targets

DEFAULT_IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache",
    ".pytest_cache", "dist", "build", ".tox", ".idea", ".ruff_cache", ".cache",
}
MAX_BYTES = 2_000_000


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0

    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def filtered(self, min_severity: Severity) -> list[Finding]:
        out = [f for f in self.findings if f.severity >= min_severity]
        out.sort(key=lambda f: (-int(f.severity), f.path, f.line or 0, f.rule_id))
        return out

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f.severity.label] = c.get(f.severity.label, 0) + 1
        return c


def _read_text(fp: str) -> str | None:
    try:
        if os.path.getsize(fp) > MAX_BYTES:
            return None
        with open(fp, "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:  # treat NUL-containing files as binary
        return None
    return raw.decode("utf-8", errors="replace")


def _dedup(findings: list[Finding]) -> list[Finding]:
    """Collapse redundant findings within a file.

    When the same rule fires both structurally (line unknown) and in the raw
    text (with a concrete line), keep the line-bound one - it is more
    actionable. Also drop exact duplicates.
    """
    lined = {(f.path, f.rule_id) for f in findings if f.line is not None}
    out: list[Finding] = []
    seen: set = set()
    for f in findings:
        if f.line is None and (f.path, f.rule_id) in lined:
            continue
        key = (f.path, f.rule_id, f.line, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan_text(text: str, path: str = "<text>", kind: str | None = None) -> list[Finding]:
    """Run all per-file detectors on an in-memory document."""
    findings = hidden.scan(text, path)
    combined = hidden.visible_and_hidden(text)
    findings += intent.scan(combined, path, visible_len=len(text))
    if kind is None:
        kind = targets.classify(path, text)
    if kind == targets.MCP:
        findings += targets.mcp_scan(text, path)
    return _dedup(findings)


def _iter_files(target: str, ignore_dirs: set[str]):
    if os.path.isfile(target):
        yield target
        return
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def scan_path(target: str, ignore_dirs: set[str] | None = None) -> ScanResult:
    ignore_dirs = DEFAULT_IGNORE_DIRS if ignore_dirs is None else ignore_dirs
    root = target if os.path.isdir(target) else os.path.dirname(target) or "."
    result = ScanResult(root=root)

    for fp in _iter_files(target, ignore_dirs):
        text = _read_text(fp)
        if text is None:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        rel = os.path.relpath(fp, root)
        result.findings.extend(scan_text(text, rel))

    ext_name = os.path.basename(os.path.normpath(target)) or "."
    result.findings.extend(trifecta.scan(result.findings, ext_name))
    return result
