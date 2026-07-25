"""Lethal-trifecta aggregation (UC501).

Simon Willison's 'lethal trifecta': an agent becomes a data-theft engine when it
simultaneously has (1) access to private data, (2) exposure to untrusted
content, and (3) a way to communicate outbound. Any one leg alone is survivable;
all three together mean a single prompt injection can exfiltrate secrets.

Agent extensions (skills, MCP tools, rules files) are, by construction, exposed
to untrusted content - that is the whole point of a tool the agent invokes on
external input. So at the extension level we raise UC501 when a scan shows both
private-data access AND an outbound channel; the untrusted-content leg is
inherent. This is a posture warning, not proof of malice.
"""
from __future__ import annotations

from ..findings import Finding
from .. import rules

_DATA_ACCESS = {"UC301", "UC302"}
_EGRESS = {"UC303", "UC304", "UC401", "UC402"}


def scan(findings: list[Finding], path: str) -> list[Finding]:
    """Given all findings for an extension, add UC501 if the trifecta is present."""
    present = {f.rule_id for f in findings}
    data = present & _DATA_ACCESS
    egress = present & _EGRESS
    if not (data and egress):
        return []
    ev = (
        f"private-data access ({', '.join(sorted(data))}) + "
        f"outbound channel ({', '.join(sorted(egress))}) in an untrusted-content surface"
    )
    return [rules.finding("UC501", path, evidence=ev)]
