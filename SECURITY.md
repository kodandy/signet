# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please use [GitHub Security Advisories](https://github.com/anthropics/signet/security/advisories/new) to report vulnerabilities privately. This ensures the issue is triaged before public disclosure.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Impact assessment (if known)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 1 week
- **Fix release**: within 2 weeks for critical issues

## Security Design

signet is a cryptographic authorization delegation layer. Security-relevant design decisions:

- **Ed25519** (via tweetnacl) for all signing operations
- **AES-256-GCM** for credential vault encryption
- **Timing-safe comparisons** for all signature/key equality checks
- **Chain-hashed audit log** (SHA-256) for tamper evidence (detection only, with the limits listed below)
- **Nonce + timestamp** for replay attack prevention
- **File permissions** (0o600/0o700) for all key material and vault data

### Threat model scope

signet protects against:

- Unauthorized agent actions (signature verification)
- Credential exposure (vault encryption + per-command injection)
- Accidental corruption and simple edits of audit entries (chain hashing — detected by `signet log --verify`, not prevented)
- Replay attacks (nonce tracking + timestamp freshness)
- Token misuse (expiration, max_uses, revocation)

signet does **not** protect against:

- Compromised host OS (root access)
- A process running as your own OS user that can write to `~/.signet/` (it can rewrite the audit log and recompute the whole hash chain, or truncate it, without `signet log --verify` noticing; there is no independent external checkpoint)
- Actions that never pass through signet (PATH wrappers can be bypassed, so the audit log is not a complete record of agent activity)
- Memory inspection of running processes
- Side-channel attacks beyond timing (power analysis, EM)

### Dependencies

signet uses minimal, well-audited dependencies:

| Package | Purpose | Security relevance |
|---------|---------|-------------------|
| tweetnacl | Ed25519 signing | Audited, no native code |
| better-sqlite3 | Audit log storage | Native binding, well-maintained |
| commander | CLI parsing | No security surface |
| yaml | Policy parsing | Input validation applied |
