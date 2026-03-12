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

Week 2: Polish, distribution, and integrations.

Week 1 (complete): crypto/, policy/, engine/, audit/, vault/, adapters/, CLI, security hardening, GTM readiness, demo GIF.

## Next Steps

1. npm publish (0.1.0)
2. CI/CD — move `docs/ci/` templates to `.github/workflows/`
3. OpenClaw / Cursor adapter improvements
4. LLM-based natural language → permission auto-generation
5. Slack/webhook approval flow
6. W3C DID/VC integration (multi-agent)

## Coding Conventions

- Bun runtime (use Bun APIs where available, maintain Node compat for npm distribution)
- Tests: `vitest` (`npm test`)
- Minimal dependencies: tweetnacl, better-sqlite3, commander, yaml
- Error messages: English
- Code comments: Japanese OK
- Type-first: define interfaces before implementation
- No classes unless necessary — prefer functions + interfaces
- All crypto operations must be synchronous (tweetnacl is sync)
- Every public function needs a test
