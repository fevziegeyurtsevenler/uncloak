# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.1] — 2026-07-26

### Changed — precision hardening (found via an open audit of 3,168 public extensions)
- `UC104` (variation-selector channel): now flags only a **run of ≥2 consecutive**
  selectors or the variation-selector *supplement*, instead of a raw count — emoji
  like ⚠️ carry one selector each and are no longer false-positived.
- `UC102` (zero-width): ignores a leading byte-order mark, emoji ZWJ sequences and
  joiners inside non-Latin scripts (e.g. Indic ZWNJ); flags only zero-width chars
  that fragment Latin/ASCII text.
- `UC202` (persona jailbreak): `DAN` is matched case-sensitively (no longer trips on
  Indonesian *"dan"* = "and"); removed the over-broad bare "you are now".
- `UC303` (network exfil): raw-IP endpoints now exclude localhost/RFC1918 private
  ranges; dropped the noisiest generic tokens (`/hook`, `collect`).

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
