"""The uncloak rule catalog.

Every finding references a rule here. Rules carry a stable id, a default
severity, a category, external framework references and remediation guidance.
Keeping the catalog in one place makes ``uncloak rules`` (and the docs) a single
source of truth, and lets downstream tools map ``UCxxx`` ids to OWASP/ATLAS.

References use short tokens:
  - OWASP LLM Top 10 (2025): LLM01..LLM10
  - MITRE ATLAS: AML.Txxxx
  - CWE: CWE-xxx
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .findings import Finding, Severity


class Category:
    HIDDEN = "hidden-text"
    INJECTION = "prompt-injection"
    EXFIL = "sensitive-data-exfiltration"
    EXECUTION = "code-execution"
    POSTURE = "posture"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    detail: str
    references: tuple[str, ...]
    remediation: str


# fmt: off
_RULES: tuple[Rule, ...] = (
    # --- UC1xx  Hidden / obfuscated text ------------------------------------
    Rule("UC101", "Unicode Tags-block smuggling", Severity.CRITICAL, Category.HIDDEN,
         "Characters in the Unicode Tags block (U+E0000-U+E007F) render as nothing "
         "but carry a full ASCII payload the model still reads. Classic way to hide "
         "instructions from a human reviewer.",
         ("LLM01", "AML.T0051.000", "CWE-655"),
         "Strip all U+E0000-U+E007F characters; treat any extension containing them as malicious."),
    Rule("UC102", "Zero-width character smuggling", Severity.HIGH, Category.HIDDEN,
         "Zero-width space/joiner/non-joiner/BOM (U+200B/C/D, U+FEFF, U+2060) can hide "
         "or fragment instructions and break naive keyword filters.",
         ("LLM01", "AML.T0051.000", "CWE-655"),
         "Normalize and strip zero-width code points before trusting the text."),
    Rule("UC103", "Bidirectional override (Trojan Source)", Severity.HIGH, Category.HIDDEN,
         "BiDi control characters (U+202A-202E, U+2066-2069) can reorder how text is "
         "displayed versus how it is parsed, hiding real intent (CVE-2021-42574).",
         ("LLM01", "CWE-1007"),
         "Reject BiDi overrides in agent instructions and bundled code."),
    Rule("UC104", "Variation selector data channel", Severity.HIGH, Category.HIDDEN,
         "Variation selectors (U+FE00-FE0F, U+E0100-E01EF) attached to carrier glyphs "
         "can encode an invisible byte stream ('emoji smuggling').",
         ("LLM01", "AML.T0051.000"),
         "Strip variation selectors that are not part of a legitimate emoji sequence."),
    Rule("UC105", "Confusable / mixed-script homoglyphs", Severity.MEDIUM, Category.HIDDEN,
         "Mixed-script confusable characters (e.g. Cyrillic 'а' for Latin 'a') can "
         "disguise commands, domains or keywords from reviewers and filters.",
         ("LLM01", "CWE-1007"),
         "Flag and review tokens mixing scripts; prefer ASCII in security-relevant text."),
    Rule("UC106", "Hidden markup payload", Severity.MEDIUM, Category.HIDDEN,
         "Instruction-like content hidden in HTML comments, tiny/'0px' styled spans, or "
         "collapsed sections that a human skims past but the model ingests.",
         ("LLM01",),
         "Render and review the full document; do not trust anything hidden from view."),
    Rule("UC107", "Encoded instruction blob", Severity.MEDIUM, Category.HIDDEN,
         "A base64/hex blob that decodes to instructions or shell content, used to slip "
         "intent past keyword scanners.",
         ("LLM01", "CWE-655"),
         "Decode and review long encoded blobs; disallow opaque payloads in extensions."),

    # --- UC2xx  Prompt injection / instruction manipulation -----------------
    Rule("UC201", "Instruction override", Severity.HIGH, Category.INJECTION,
         "Text that tells the agent to ignore, disregard or supersede prior/system "
         "instructions - the canonical prompt-injection primitive.",
         ("LLM01", "AML.T0051.000"),
         "Extensions must not attempt to override system or user instructions."),
    Rule("UC202", "Role / persona reassignment", Severity.MEDIUM, Category.INJECTION,
         "Attempts to re-cast the model into an unrestricted persona ('you are now DAN', "
         "'developer mode') to strip safety constraints.",
         ("LLM01",),
         "Reject persona-jailbreak framing in extension instructions."),
    Rule("UC203", "Stealth / hide-from-user instruction", Severity.HIGH, Category.INJECTION,
         "Instructions telling the agent to act 'without telling the user' or to conceal "
         "what it did - a hallmark of malicious extensions.",
         ("LLM01", "AML.T0051.000"),
         "Any 'do not tell the user' directive should block installation."),
    Rule("UC204", "Tool-poisoning in description/parameters", Severity.CRITICAL, Category.INJECTION,
         "An MCP tool description or parameter text that carries hidden instructions to "
         "the agent (the tool description is read by the model, not just humans).",
         ("LLM01", "AML.T0051.001"),
         "Tool descriptions must describe behavior only; never embed agent directives."),
    Rule("UC205", "Trigger-conditioned behavior (rug-pull)", Severity.HIGH, Category.INJECTION,
         "Logic that changes behavior on a hidden trigger ('if the user asks X, secretly "
         "do Y') - enables time-bombed / rug-pull extensions.",
         ("LLM01", "AML.T0051.000"),
         "Reject conditional hidden behaviors keyed on user phrases or dates."),

    # --- UC3xx  Sensitive data & exfiltration -------------------------------
    Rule("UC301", "Credential / secret access", Severity.HIGH, Category.EXFIL,
         "References to secrets, API keys, tokens or password material that an "
         "extension has no legitimate reason to read.",
         ("LLM06", "LLM02", "AML.T0057"),
         "Extensions should not read credentials; scope secrets away from the agent."),
    Rule("UC302", "Sensitive file path access", Severity.HIGH, Category.EXFIL,
         "Paths to high-value secrets (.env, ~/.ssh, id_rsa, ~/.aws, keychains, browser "
         "cookie stores) referenced by an extension.",
         ("LLM06", "AML.T0057"),
         "Deny extension access to sensitive paths; use an egress/file allowlist."),
    Rule("UC303", "Network exfiltration endpoint", Severity.HIGH, Category.EXFIL,
         "Outbound POST/GET to webhook, collector, pastebin or request-catcher hosts - a "
         "channel to send stolen data off the machine.",
         ("LLM06", "AML.T0024", "CWE-200"),
         "Block network egress from extensions except to explicit allowlisted hosts."),
    Rule("UC304", "Out-of-band (DNS) exfiltration", Severity.MEDIUM, Category.EXFIL,
         "DNS-based or nested-subdomain exfil patterns that leak data even when HTTP "
         "egress is blocked.",
         ("LLM06", "AML.T0024"),
         "Monitor and restrict DNS from agent sandboxes."),

    # --- UC4xx  Code execution / supply chain -------------------------------
    Rule("UC401", "Shell execution / pipe-to-shell", Severity.HIGH, Category.EXECUTION,
         "Direct shell invocation or piping remote content into a shell "
         "(`curl ... | bash`) - remote code execution on the host.",
         ("LLM05", "AML.T0011", "CWE-78"),
         "Extensions should not spawn shells or execute fetched content."),
    Rule("UC402", "Remote fetch-and-execute", Severity.HIGH, Category.EXECUTION,
         "Downloading a script/binary and running it, pulling attacker-controlled code "
         "at runtime.",
         ("LLM05", "AML.T0010", "CWE-494"),
         "Pin and vendor dependencies; never fetch-and-run at agent runtime."),
    Rule("UC403", "Bundled executable script", Severity.MEDIUM, Category.EXECUTION,
         "An extension ships an executable script that the agent may run without the "
         "code ever entering the review context.",
         ("LLM05", "CWE-829"),
         "Review every bundled script; prefer extensions with no executable payload."),
    Rule("UC404", "Untrusted package install", Severity.MEDIUM, Category.EXECUTION,
         "Runtime install of packages from untrusted sources (curl'd installers, "
         "unpinned pip/npm from arbitrary URLs).",
         ("LLM05", "CWE-829"),
         "Install only pinned dependencies from trusted registries at build time."),

    # --- UC5xx  Aggregate posture -------------------------------------------
    Rule("UC501", "Lethal trifecta", Severity.CRITICAL, Category.POSTURE,
         "The extension combines private-data access, exposure to untrusted content, and "
         "an outbound channel - the three ingredients that turn injection into data "
         "theft (Simon Willison's 'lethal trifecta').",
         ("LLM01", "LLM06", "AML.T0024"),
         "Break at least one leg: remove secret access, isolate untrusted input, or cut egress."),
    Rule("UC502", "Overbroad permissions", Severity.LOW, Category.POSTURE,
         "The extension requests broad tool/filesystem/network scope beyond its stated "
         "purpose, enlarging blast radius.",
         ("LLM08", "AML.T0053"),
         "Grant least privilege; narrow allowed-tools and paths to what is needed."),
)
# fmt: on

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def get(rule_id: str) -> Rule:
    return RULES[rule_id]


def all_rules() -> tuple[Rule, ...]:
    return _RULES


def finding(
    rule_id: str,
    path: str,
    line: Optional[int] = None,
    evidence: str = "",
    severity: Optional[Severity] = None,
    detail: Optional[str] = None,
) -> Finding:
    """Build a :class:`Finding` from a catalog rule, filling in shared metadata."""
    r = RULES[rule_id]
    return Finding(
        rule_id=r.id,
        title=r.title,
        severity=severity if severity is not None else r.severity,
        path=path,
        line=line,
        evidence=evidence,
        detail=detail if detail is not None else r.detail,
        category=r.category,
        references=list(r.references),
        remediation=r.remediation,
    )
