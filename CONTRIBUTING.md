# Contributing to uncloak

Thanks for helping make agent extensions safer. The most valuable contributions
are **new evasion techniques and detection rules** — the attack surface moves
fast.

## Dev setup

```bash
git clone https://github.com/fevziegeyurtsevenler/uncloak
cd uncloak
pip install -e ".[dev]"
pytest -q
```

No runtime dependencies; please keep it that way (standard library only). Tests
should stay fast and hermetic.

## Adding a rule

1. Add a `Rule(...)` to the catalog in `src/uncloak/rules.py` with a stable id
   (`UCxxx`), a sensible default severity, and OWASP LLM / MITRE ATLAS / CWE
   references.
2. Implement detection in the right detector:
   - invisible / obfuscated code points → `detectors/hidden.py`
   - pattern-based intent → add a `(rule_id, pattern)` to `detectors/intent.py`
   - MCP structure-aware → `targets.py`
3. Add a fixture + unit test proving it fires **and** a clean case proving it
   doesn't false-positive.
4. Run `uncloak rules` and `pytest -q`.

## Guidelines

- **Precision matters.** A noisy scanner gets ignored. Prefer a specific pattern
  and a matching negative test over a broad one.
- **Explain the risk.** Every rule needs a one-line `detail` and a `remediation`.
- Keep evidence snippets short and safe to print.

## Reporting real malicious extensions

Please do that responsibly — see [SECURITY.md](SECURITY.md). Do not open public
issues that link to live payloads.
