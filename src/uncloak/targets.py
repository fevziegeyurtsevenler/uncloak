"""Target detection and structure-aware parsing.

uncloak scans plain text for every file, but some extension formats deserve
structure-aware handling:

* **MCP config / manifest** - tool ``description`` fields are read by the model,
  so hidden instructions there are *tool poisoning* (UC204), and server
  ``command``/``args`` are an execution surface (UC401/UC402/UC404).
* **Agent Skill (SKILL.md)** and **rules files** (.cursorrules, CLAUDE.md, ...)
  are instruction documents; they are scanned as text but classified so reports
  read clearly.
"""
from __future__ import annotations

import json
import os
import re

from .detectors import hidden, intent
from .findings import Finding, Severity
from . import rules

SKILL = "skill"
MCP = "mcp"
RULES_FILE = "rules"
TEXT = "text"

_RULES_FILENAMES = {
    ".cursorrules", ".windsurfrules", ".clinerules", ".aider.conf.yml",
    "agents.md", "claude.md", "copilot-instructions.md", "gemini.md",
}
_MCP_FILENAMES = {"claude_desktop_config.json", ".mcp.json", "mcp.json"}


def classify(path: str, text: str) -> str:
    base = os.path.basename(path).lower()
    if base == "skill.md" or re.search(r"(^|/)skills?/", path.replace(os.sep, "/").lower()):
        return SKILL
    if base in _MCP_FILENAMES or (base.endswith(".json") and '"mcpServers"' in text):
        return MCP
    if base.endswith(".json") and re.search(r'"tools"\s*:\s*\[', text) and '"inputSchema"' in text:
        return MCP
    if base in _RULES_FILENAMES:
        return RULES_FILE
    return TEXT


# --- MCP structure-aware scanning ------------------------------------------
_EXEC_RULES = {"UC401", "UC402", "UC404"}


def _walk(node, path_keys=()):
    """Yield (key, value, path_keys) for every string leaf in a JSON structure."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, path_keys + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, path_keys + (str(i),))
    elif isinstance(node, str):
        yield path_keys[-1] if path_keys else "", node, path_keys


def mcp_scan(text: str, path: str) -> list[Finding]:
    """Structure-aware findings for an MCP config/manifest."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []  # malformed JSON: plain-text scan still runs in the engine

    findings: list[Finding] = []
    commands: list[str] = []
    for key, value, keys in _walk(data):
        dotted = ".".join(keys)
        # Tool descriptions / instructions are model-facing -> tool poisoning.
        if key in ("description", "instructions") or key.endswith("Description"):
            hits = intent.find(value, {"UC201", "UC202", "UC203", "UC205"})
            tag_chars = [c for c in value if 0xE0000 <= ord(c) <= 0xE007F]
            if hits or tag_chars:
                why = "hidden instruction" if tag_chars else f"injection markers ({', '.join(r for r, _ in hits)})"
                findings.append(rules.finding(
                    "UC204", path,
                    evidence=f"{dotted}: {why} in model-facing description"))
        # Server launch commands are an execution surface.
        if key == "command" or (len(keys) >= 2 and keys[-2] == "args"):
            commands.append(value)

    joined = " ".join(commands)
    for rid, m in intent.find(joined, _EXEC_RULES):
        findings.append(rules.finding(rid, path, evidence=f"server command: {m.group(0)[:100]}"))
    return findings


# --- SKILL.md frontmatter ---------------------------------------------------
def skill_meta(text: str) -> dict:
    """Best-effort parse of a SKILL.md YAML frontmatter (name/description/tools)."""
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not m:
        return {}
    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        kv = re.match(r"\s*([A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$", line)
        if kv:
            meta[kv.group(1).lower()] = kv.group(2)
    return meta
