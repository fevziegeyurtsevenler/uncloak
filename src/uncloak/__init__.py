"""uncloak - reveal hidden prompt injection & supply-chain risks in AI agent extensions.

Public API:
    >>> from uncloak import scan_path, scan_text
    >>> result = scan_path("./my-skill")
    >>> [f.rule_id for f in result.findings]
"""
from .engine import ScanResult, scan_path, scan_text
from .findings import Finding, Severity
from .version import __version__

__all__ = ["scan_path", "scan_text", "ScanResult", "Finding", "Severity", "__version__"]
