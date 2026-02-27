# signet

"Your agent doesn't need your keys. It needs a keyhole."

Cryptographic authorization delegation layer for local AI agents.
Lightweight implementation of South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025).

## What this does

AI agents (Claude Code, OpenClaw, Cursor) get their own Ed25519 keypair. Users issue signed delegation tokens defining what each agent can do. Every action request is signed, every approval is signed. Tamper-proof audit trail.

**Not a sandbox. Not a policy engine. A cryptographic trust layer.**

## Tech Stack

- **Runtime**: Bun
- **Crypto**: tweetnacl (Ed25519)
- **Storage**: better-sqlite3 (audit logs)
- **CLI**: Commander.js
- **Policy**: YAML (parsed with yaml package)
- **Distribution**: npm

## Architecture

See `docs/ARCHITECTURE.md` for full module design, type definitions, and data flow.
See `docs/CONTEXT.md` for design rationale and competitive analysis.

## Project Structure

```
src/
  crypto/       — Ed25519 keypair management + delegation tokens
  policy/       — YAML parser + glob/pattern matching
  engine/       — Core evaluation loop + CLI approval prompt
  vault/        — Credential isolation (.env evacuation + temp injection)
  audit/        — SQLite logger with chain hashing
  adapters/     — Claude Code, OpenClaw, generic (PATH wrapper)
  index.ts      — CLI entry point
templates/      — Preset policy files (node.yml, python.yml, general.yml)
test/           — Tests per module
docs/           — Architecture + context docs
```

## Current Phase

MVP Week 1: Implement crypto/, policy/, engine/, audit/ core modules.

## Implementation Order

1. `crypto/keys.ts` — keypair gen/store/load
2. `crypto/delegation.ts` — token create/verify
3. `policy/parser.ts` — YAML → Scope
4. `policy/matcher.ts` — glob matching
5. `engine/evaluator.ts` — request → decision
6. `audit/logger.ts` — SQLite + chain hash

## Coding Conventions

- Bun runtime (use Bun APIs where available, maintain Node compat for npm distribution)
- Tests: `bun:test`
- Minimal dependencies: tweetnacl, better-sqlite3, commander, yaml
- Error messages: English
- Code comments: Japanese OK
- Type-first: define interfaces before implementation
- No classes unless necessary — prefer functions + interfaces
- All crypto operations must be synchronous (tweetnacl is sync)
- Every public function needs a test
