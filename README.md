# signet

**"Your agent doesn't need your keys. It needs a keyhole."**

Cryptographic authorization delegation layer for local AI agents.
Lightweight implementation of [South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025)](https://arxiv.org/abs/2501.09674).

---

## What this does

AI agents (Claude Code, Cursor, etc.) get their own Ed25519 keypair.
You issue signed delegation tokens defining what each agent can do.
Every action request is signed, every approval is signed.
Tamper-proof audit trail.

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

```bash
# Install
npm install -g signet

# Initialize (generates keys + policy file)
signet init

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
signet init [--template <name>] [--claude-code]   Setup keys + policy
signet activate                                    Enable vault + policies
signet deactivate                                  Restore credentials
signet status                                      Show current state
signet check "<command>"                           Dry-run policy check
signet log [--verify] [--export json|csv] [-n N]   Audit log
signet keys list                                   List agent keys
```

## How it works

### Decision flow

```
ActionRequest received
  → Verify agent signature (Ed25519)
  → Validate DelegationToken (expired? revoked?)
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
1. `.env` files are encrypted and moved to `~/.signet/vault/`
2. Credential env vars are cleared from the process
3. Agents cannot access credentials directly
4. Approved credential use is temporarily injected per-command

## Claude Code Integration

```bash
signet init --claude-code
```

Generates:
- `.claude/settings.json` with deny/ask rules matching your policy
- `CLAUDE.md` section with security policy documentation

## Architecture

```
src/
  crypto/         Ed25519 keypair management + delegation tokens
  policy/         YAML parser + glob/pattern matching
  engine/         Core evaluation loop
  vault/          Credential isolation (.env evacuation)
  audit/          SQLite logger with chain hashing
  adapters/       Claude Code, generic (PATH wrapper)
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

## Differentiation

|  | Sandbox | Cerbos/Permit.io | 1Password | **signet** |
|--|---------|-------------------|-----------|------------|
| Approach | Containment | Policy engine | Key vault | **Crypto delegation** |
| Target | Single agent | Enterprise | Browser | **Local dev** |
| Setup | Config | Docker+IdP | SaaS | **`npx signet init`** |
| Signatures | None | None | Partial | **All operations** |
| Non-repudiation | No | No | No | **Yes** |
| Multi-agent | No | Yes | No | **Planned** |

## Tech Stack

- **Runtime**: Node.js / Bun
- **Crypto**: [tweetnacl](https://github.com/nicedrop/tweetnacl-js) (Ed25519)
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

## Roadmap

- [x] Core: crypto, policy, engine, audit
- [x] UX: CLI, vault, adapters, templates
- [ ] LLM-based natural language → structured permission auto-generation
- [ ] OpenClaw / Cursor adapters
- [ ] Slack/webhook approval flow
- [ ] W3C DID/VC integration (multi-agent)

## License

MIT
