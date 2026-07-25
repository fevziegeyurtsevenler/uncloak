# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — 2026-07-25

Initial public release.

### Added
- Scanner for AI agent extensions: Agent/Claude **Skills** (`SKILL.md`), **MCP**
  configs/manifests, and **rules files** (`.cursorrules`, `CLAUDE.md`, `AGENTS.md`).
- 22-rule catalog (`UC101`–`UC502`) across hidden-text, prompt-injection,
  data-exfiltration, code-execution and posture classes, mapped to OWASP LLM
  Top 10 and MITRE ATLAS.
- Invisible-text detection: Unicode Tags block, zero-width, bidi overrides,
  variation-selector data channels, confusable homoglyphs, encoded blobs — with
  payload decoding.
- MCP structure-aware analysis: tool-description poisoning and server-command
  execution surfaces.
- Lethal-trifecta aggregation (`UC501`).
- Output formats: terminal, JSON, SARIF 2.1.0. CI-friendly exit codes.
- GitHub Action (`action.yml`) and CI workflow.
- Zero runtime dependencies; Python 3.9+.
