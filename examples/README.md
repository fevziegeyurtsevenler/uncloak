# Examples

Try `uncloak` against the sample extensions bundled in this repo. These are the
same fixtures the test suite uses — safe to scan, with dummy hosts and no real
secrets.

```bash
# A benign skill — should come back clean:
uncloak scan tests/fixtures/clean

# A skill that looks innocent but hides an instruction in invisible Unicode:
uncloak scan tests/fixtures/malicious

# A poisoned MCP config (tool-description poisoning + curl|bash launch command):
uncloak scan tests/fixtures/mcp/poisoned.json

# A rules file with a stealth exfil instruction:
uncloak scan tests/fixtures/rules/.cursorrules
```

Machine-readable output for CI:

```bash
uncloak scan tests/fixtures/mcp/poisoned.json --format json
uncloak scan tests/fixtures/mcp/poisoned.json --format sarif -o uncloak.sarif
```

> The "malicious" skill's only *visible* text is a thank-you line. Everything
> `uncloak` reports on it is hidden from the human eye — which is the whole point.
