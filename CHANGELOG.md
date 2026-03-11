# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-11

### Added

- Ed25519 keypair generation, storage, and loading (`crypto/keys.ts`)
- Delegation token creation and verification with expiration, max_uses, revocation (`crypto/delegation.ts`)
- YAML policy parser with schema validation (`policy/parser.ts`)
- Glob pattern matching for filesystem, network, shell, and credential scopes (`policy/matcher.ts`)
- Core evaluation engine with signed action decisions (`engine/evaluator.ts`)
- SQLite audit logger with chain-hashed tamper-evident records (`audit/logger.ts`)
- Credential vault with AES-256-GCM encryption and per-command injection (`vault/manager.ts`)
- Claude Code adapter (settings.json generation) (`adapters/claude-code.ts`)
- Cursor adapter (`adapters/cursor.ts`)
- Generic PATH wrapper adapter (`adapters/generic.ts`)
- CLI with full command set: init, activate, check, log, delegate, keys, scan, demo, adapt
- Smart init with auto-detection of project type, .env files, git remotes (`--smart`)
- Interactive demo mode (`signet demo`)
- Policy templates: node.yml, python.yml, general.yml

### Security

- Timing-safe comparisons for all signature and key equality checks
- Replay attack prevention via nonce tracking and timestamp freshness (5-minute window)
- ReDoS prevention in glob pattern compilation
- Shell injection prevention in credential name validation
- Null byte handling in path matching
- Legacy CBC vault format rejected (AES-256-GCM only)
- File permissions enforced (0o600 for keys, 0o700 for vault directory)
- Secrets redacted from command output
