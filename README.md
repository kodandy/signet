# signet

**"Your agent doesn't need your keys. It needs a keyhole."**

Cryptographic authorization delegation layer for local AI agents.
Lightweight implementation of [South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025)](https://arxiv.org/abs/2501.09674).

<p align="center">
  <img src="demo/signet-demo.gif" alt="signet demo" width="720">
</p>

---

## What this does

AI agents (Claude Code, Cursor, etc.) get their own Ed25519 keypair.
You issue signed delegation tokens defining what each agent can do.
Every action request is signed, every approval is signed.
Tamper-evident audit trail ([what that does and does not guarantee](#what-the-audit-log-does-and-does-not-guarantee)).

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
# Try the interactive demo (no setup needed)
npx ai-signet demo

# Install
npm install -g ai-signet

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
  signet adapt generic                               Generate PATH wrapper scripts
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

Every log entry stores a SHA-256 hash computed over the previous entry's hash, the request, and the decision, creating a tamper-evident chain. `signet log --verify` recomputes the chain and reports every entry whose contents or link to the previous entry no longer match.

### What the audit log does and does not guarantee

The audit log is **tamper-evident, not tamper-proof**. A passing `signet log --verify` means the stored chain is internally consistent — nothing more.

- **Detected**: accidental corruption and simple edits — changing a stored request or decision, or inserting or removing an entry in the middle of the log, without recomputing the hashes that follow.
- **Not detected — full recomputation**: keys, tokens, and the audit database all live under `~/.signet/` and belong to your OS user. Any process running as that user that can write to `~/.signet/` — including a prompt-injected agent that can run arbitrary commands — can rewrite entries and recompute every hash from the first entry onward. `--verify` then passes.
- **Not detected — truncation**: removing the most recent entries, or deleting the whole log, leaves a valid (shorter) chain. Nothing outside the database records the latest hash or the number of entries.
- **Signatures are not re-checked**: `--verify` validates the hash chain only. It does not verify the Ed25519 signatures stored inside the entries.
- **Coverage is not guaranteed**: only requests that are evaluated by signet and handed to the audit logger are recorded. The PATH wrappers generated by `signet adapt generic` can be bypassed (for example by calling a binary by its absolute path or by changing `PATH`), so the log is not a complete record of everything an agent did.

There is no independent external checkpoint, so the guarantee ends here. If you need to detect rewriting by something running as your own user, you have to anchor the chain yourself: periodically copy the latest `chain_hash` (see `signet log --export json`) to a place the agent cannot write to, and compare it later. signet does not do this for you.

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
| Setup | Config | Docker+IdP | SaaS | **`npx ai-signet init`** |
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
