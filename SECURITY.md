# Security policy

## Reporting a vulnerability in uncloak

If you find a bug in `uncloak` itself (e.g. a bypass that lets a malicious
extension evade detection), please report it privately:

- Use **GitHub Security Advisories** ("Report a vulnerability") on this repo, or
- email the maintainer (see the GitHub profile).

Please do not open a public issue with a working bypass until a fix is available.

## Reporting a malicious real-world extension

`uncloak` exists to surface malicious agent extensions. If you discover one in
the wild (a marketplace skill, MCP server, etc.):

1. Report it to the **platform/marketplace** hosting it first.
2. Do **not** post live payloads publicly. If you want a detection rule added,
   open an issue describing the *technique* (redacted), or send a sanitized
   fixture privately.

## Scope

`uncloak` is a static analysis aid, not a guarantee. It is one layer of defense;
see [`docs/attacks.md`](docs/attacks.md) for the recommended defense-in-depth
posture.
