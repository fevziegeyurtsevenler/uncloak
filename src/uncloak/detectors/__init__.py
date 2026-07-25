"""Detectors turn text (and parsed structure) into findings.

Each detector is a pure function ``(text, path) -> list[Finding]`` (or a small
variation) so they are trivial to unit-test in isolation.
"""
from . import hidden, intent, trifecta

__all__ = ["hidden", "intent", "trifecta"]
