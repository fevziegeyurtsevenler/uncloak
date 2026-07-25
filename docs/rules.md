# uncloak rule catalog

Every finding maps to one rule id below. Generated from the catalog (`uncloak rules --format json`) — do not edit by hand.


## hidden-text

| id | severity | title | references |
|----|----------|-------|------------|
| `UC101` | critical | Unicode Tags-block smuggling | LLM01, AML.T0051.000, CWE-655 |
| `UC102` | high | Zero-width character smuggling | LLM01, AML.T0051.000, CWE-655 |
| `UC103` | high | Bidirectional override (Trojan Source) | LLM01, CWE-1007 |
| `UC104` | high | Variation selector data channel | LLM01, AML.T0051.000 |
| `UC105` | medium | Confusable / mixed-script homoglyphs | LLM01, CWE-1007 |
| `UC106` | medium | Hidden markup payload | LLM01 |
| `UC107` | medium | Encoded instruction blob | LLM01, CWE-655 |

## prompt-injection

| id | severity | title | references |
|----|----------|-------|------------|
| `UC201` | high | Instruction override | LLM01, AML.T0051.000 |
| `UC202` | medium | Role / persona reassignment | LLM01 |
| `UC203` | high | Stealth / hide-from-user instruction | LLM01, AML.T0051.000 |
| `UC204` | critical | Tool-poisoning in description/parameters | LLM01, AML.T0051.001 |
| `UC205` | high | Trigger-conditioned behavior (rug-pull) | LLM01, AML.T0051.000 |

## sensitive-data-exfiltration

| id | severity | title | references |
|----|----------|-------|------------|
| `UC301` | high | Credential / secret access | LLM06, LLM02, AML.T0057 |
| `UC302` | high | Sensitive file path access | LLM06, AML.T0057 |
| `UC303` | high | Network exfiltration endpoint | LLM06, AML.T0024, CWE-200 |
| `UC304` | medium | Out-of-band (DNS) exfiltration | LLM06, AML.T0024 |

## code-execution

| id | severity | title | references |
|----|----------|-------|------------|
| `UC401` | high | Shell execution / pipe-to-shell | LLM05, AML.T0011, CWE-78 |
| `UC402` | high | Remote fetch-and-execute | LLM05, AML.T0010, CWE-494 |
| `UC403` | medium | Bundled executable script | LLM05, CWE-829 |
| `UC404` | medium | Untrusted package install | LLM05, CWE-829 |

## posture

| id | severity | title | references |
|----|----------|-------|------------|
| `UC501` | critical | Lethal trifecta | LLM01, LLM06, AML.T0024 |
| `UC502` | low | Overbroad permissions | LLM08, AML.T0053 |

## Details

### UC101 — Unicode Tags-block smuggling
*severity:* **critical** · *category:* hidden-text · *refs:* LLM01, AML.T0051.000, CWE-655

Characters in the Unicode Tags block (U+E0000-U+E007F) render as nothing but carry a full ASCII payload the model still reads. Classic way to hide instructions from a human reviewer.

**Remediation:** Strip all U+E0000-U+E007F characters; treat any extension containing them as malicious.

### UC102 — Zero-width character smuggling
*severity:* **high** · *category:* hidden-text · *refs:* LLM01, AML.T0051.000, CWE-655

Zero-width space/joiner/non-joiner/BOM (U+200B/C/D, U+FEFF, U+2060) can hide or fragment instructions and break naive keyword filters.

**Remediation:** Normalize and strip zero-width code points before trusting the text.

### UC103 — Bidirectional override (Trojan Source)
*severity:* **high** · *category:* hidden-text · *refs:* LLM01, CWE-1007

BiDi control characters (U+202A-202E, U+2066-2069) can reorder how text is displayed versus how it is parsed, hiding real intent (CVE-2021-42574).

**Remediation:** Reject BiDi overrides in agent instructions and bundled code.

### UC104 — Variation selector data channel
*severity:* **high** · *category:* hidden-text · *refs:* LLM01, AML.T0051.000

Variation selectors (U+FE00-FE0F, U+E0100-E01EF) attached to carrier glyphs can encode an invisible byte stream ('emoji smuggling').

**Remediation:** Strip variation selectors that are not part of a legitimate emoji sequence.

### UC105 — Confusable / mixed-script homoglyphs
*severity:* **medium** · *category:* hidden-text · *refs:* LLM01, CWE-1007

Mixed-script confusable characters (e.g. Cyrillic 'а' for Latin 'a') can disguise commands, domains or keywords from reviewers and filters.

**Remediation:** Flag and review tokens mixing scripts; prefer ASCII in security-relevant text.

### UC106 — Hidden markup payload
*severity:* **medium** · *category:* hidden-text · *refs:* LLM01

Instruction-like content hidden in HTML comments, tiny/'0px' styled spans, or collapsed sections that a human skims past but the model ingests.

**Remediation:** Render and review the full document; do not trust anything hidden from view.

### UC107 — Encoded instruction blob
*severity:* **medium** · *category:* hidden-text · *refs:* LLM01, CWE-655

A base64/hex blob that decodes to instructions or shell content, used to slip intent past keyword scanners.

**Remediation:** Decode and review long encoded blobs; disallow opaque payloads in extensions.

### UC201 — Instruction override
*severity:* **high** · *category:* prompt-injection · *refs:* LLM01, AML.T0051.000

Text that tells the agent to ignore, disregard or supersede prior/system instructions - the canonical prompt-injection primitive.

**Remediation:** Extensions must not attempt to override system or user instructions.

### UC202 — Role / persona reassignment
*severity:* **medium** · *category:* prompt-injection · *refs:* LLM01

Attempts to re-cast the model into an unrestricted persona ('you are now DAN', 'developer mode') to strip safety constraints.

**Remediation:** Reject persona-jailbreak framing in extension instructions.

### UC203 — Stealth / hide-from-user instruction
*severity:* **high** · *category:* prompt-injection · *refs:* LLM01, AML.T0051.000

Instructions telling the agent to act 'without telling the user' or to conceal what it did - a hallmark of malicious extensions.

**Remediation:** Any 'do not tell the user' directive should block installation.

### UC204 — Tool-poisoning in description/parameters
*severity:* **critical** · *category:* prompt-injection · *refs:* LLM01, AML.T0051.001

An MCP tool description or parameter text that carries hidden instructions to the agent (the tool description is read by the model, not just humans).

**Remediation:** Tool descriptions must describe behavior only; never embed agent directives.

### UC205 — Trigger-conditioned behavior (rug-pull)
*severity:* **high** · *category:* prompt-injection · *refs:* LLM01, AML.T0051.000

Logic that changes behavior on a hidden trigger ('if the user asks X, secretly do Y') - enables time-bombed / rug-pull extensions.

**Remediation:** Reject conditional hidden behaviors keyed on user phrases or dates.

### UC301 — Credential / secret access
*severity:* **high** · *category:* sensitive-data-exfiltration · *refs:* LLM06, LLM02, AML.T0057

References to secrets, API keys, tokens or password material that an extension has no legitimate reason to read.

**Remediation:** Extensions should not read credentials; scope secrets away from the agent.

### UC302 — Sensitive file path access
*severity:* **high** · *category:* sensitive-data-exfiltration · *refs:* LLM06, AML.T0057

Paths to high-value secrets (.env, ~/.ssh, id_rsa, ~/.aws, keychains, browser cookie stores) referenced by an extension.

**Remediation:** Deny extension access to sensitive paths; use an egress/file allowlist.

### UC303 — Network exfiltration endpoint
*severity:* **high** · *category:* sensitive-data-exfiltration · *refs:* LLM06, AML.T0024, CWE-200

Outbound POST/GET to webhook, collector, pastebin or request-catcher hosts - a channel to send stolen data off the machine.

**Remediation:** Block network egress from extensions except to explicit allowlisted hosts.

### UC304 — Out-of-band (DNS) exfiltration
*severity:* **medium** · *category:* sensitive-data-exfiltration · *refs:* LLM06, AML.T0024

DNS-based or nested-subdomain exfil patterns that leak data even when HTTP egress is blocked.

**Remediation:** Monitor and restrict DNS from agent sandboxes.

### UC401 — Shell execution / pipe-to-shell
*severity:* **high** · *category:* code-execution · *refs:* LLM05, AML.T0011, CWE-78

Direct shell invocation or piping remote content into a shell (`curl ... | bash`) - remote code execution on the host.

**Remediation:** Extensions should not spawn shells or execute fetched content.

### UC402 — Remote fetch-and-execute
*severity:* **high** · *category:* code-execution · *refs:* LLM05, AML.T0010, CWE-494

Downloading a script/binary and running it, pulling attacker-controlled code at runtime.

**Remediation:** Pin and vendor dependencies; never fetch-and-run at agent runtime.

### UC403 — Bundled executable script
*severity:* **medium** · *category:* code-execution · *refs:* LLM05, CWE-829

An extension ships an executable script that the agent may run without the code ever entering the review context.

**Remediation:** Review every bundled script; prefer extensions with no executable payload.

### UC404 — Untrusted package install
*severity:* **medium** · *category:* code-execution · *refs:* LLM05, CWE-829

Runtime install of packages from untrusted sources (curl'd installers, unpinned pip/npm from arbitrary URLs).

**Remediation:** Install only pinned dependencies from trusted registries at build time.

### UC501 — Lethal trifecta
*severity:* **critical** · *category:* posture · *refs:* LLM01, LLM06, AML.T0024

The extension combines private-data access, exposure to untrusted content, and an outbound channel - the three ingredients that turn injection into data theft (Simon Willison's 'lethal trifecta').

**Remediation:** Break at least one leg: remove secret access, isolate untrusted input, or cut egress.

### UC502 — Overbroad permissions
*severity:* **low** · *category:* posture · *refs:* LLM08, AML.T0053

The extension requests broad tool/filesystem/network scope beyond its stated purpose, enlarging blast radius.

**Remediation:** Grant least privilege; narrow allowed-tools and paths to what is needed.
