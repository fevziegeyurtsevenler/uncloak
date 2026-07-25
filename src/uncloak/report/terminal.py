"""Human-friendly terminal renderer with optional ANSI colour."""
from __future__ import annotations  # noqa: F404

import os
import sys

from ..engine import ScanResult
from ..findings import Finding, Severity

_TTY = (sys.stdout.isatty() or os.environ.get("FORCE_COLOR")) and not os.environ.get("NO_COLOR")


def _c(code: str, s: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if _TTY else s


def _bold(s): return _c("1", s)
def _dim(s): return _c("2", s)
def _red(s): return _c("1;31", s)
def _amber(s): return _c("33", s)
def _blue(s): return _c("34", s)
def _green(s): return _c("32", s)
def _mag(s): return _c("35", s)

_SEV_STYLE = {
    Severity.CRITICAL: _red,
    Severity.HIGH: _red,
    Severity.MEDIUM: _amber,
    Severity.LOW: _blue,
    Severity.INFO: _dim,
}


def _sev_tag(sev: Severity) -> str:
    return _SEV_STYLE[sev](f"{sev.label.upper():>8}")


def render(result: ScanResult, findings: list[Finding], show_refs: bool = False) -> str:
    lines: list[str] = []
    lines.append(f"{_mag('✻')} {_bold('uncloak')} {_dim('· hidden prompt-injection & supply-chain scan for AI agent extensions')}")
    lines.append(_dim(f"  target: {result.root}   files: {result.files_scanned} scanned, {result.files_skipped} skipped"))
    lines.append("")

    if not findings:
        lines.append(_green("  ✓ clean") + _dim("  — no hidden text or dangerous intent detected."))
        lines.append("")
        return "\n".join(lines)

    for f in findings:
        loc = f.path + (f":{f.line}" if f.line else "")
        lines.append(f"  {_sev_tag(f.severity)}  {_bold(f.rule_id)}  {f.title}")
        lines.append(f"            {_dim(loc)}")
        if f.evidence:
            lines.append(f"            {_mag(f.evidence)}")
        if f.detail:
            lines.append(f"            {_dim(f.detail)}")
        if show_refs and f.references:
            lines.append(f"            {_dim('refs: ' + ', '.join(f.references))}")
        lines.append("")

    counts = result.counts()
    order = ["critical", "high", "medium", "low", "info"]
    summary = "  ".join(f"{counts[k]} {k}" for k in order if counts.get(k))
    lines.append(_dim("  ─────────────────────────────────────────────"))
    worst = result.worst()
    if worst >= Severity.HIGH:
        verdict = _red(_bold("  ✗ HIGH RISK")) + _dim("  — do not install without review.")
    elif worst >= Severity.MEDIUM:
        verdict = _amber(_bold("  ⚠ REVIEW")) + _dim("  — suspicious patterns found.")
    else:
        verdict = _blue(_bold("  · minor")) + _dim("  — low-severity notes only.")
    lines.append(f"  {summary}")
    lines.append(verdict)
    lines.append("")
    return "\n".join(lines)
