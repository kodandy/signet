# signet: Design Context

## Why this exists

AI agents (Claude Code, OpenClaw, Cursor, Cowork) operate on users' local machines with broad system access. Current security approaches have structural limitations:

- **Sandboxes** (Claude Code bubblewrap/seatbelt): Static allow/deny on directories and domains. Can't use conversation context for decisions. Breaks down with multiple agents.
- **MCP policy engines** (Cerbos, Permit.io): Enterprise-focused, require Docker + IdP + OAuth. No individual developer would use these locally.
- **Credential managers** (1Password Agentic Autofill): Browser-only. Doesn't cover shell, filesystem, or API access.
- **Command blocklists**: Trivially bypassed. Blocking `rm -rf` doesn't block `find / -delete`.

The real threats are credential exfiltration and unauthorized use of credentials, not specific commands.

## Core insight

Treat AI agents as separate systems, not extensions of the user. All interactions should be cryptographically authenticated, just like SSH treats remote machines.

This means:
1. Every agent gets its own keypair
2. User issues signed delegation tokens defining what the agent can do
3. Every action request is signed by the agent, every approval is signed by the user
4. Tamper-proof audit trail via chain hashing

## Key design decisions

### Why cryptographic signing over sandboxing
- Sandbox = static walls. Signing = per-request contextual authorization
- Sandbox can't express "use this credential 5 times within 4 hours for git push only"
- Signing produces non-repudiable audit logs (sandbox logs are mutable)
- Signing scales to multi-agent delegation chains; sandboxes require "holes in walls"

### Why UX-first
- Security tools fail when they add friction
- Target: reduce permission prompts by 95% vs current Claude Code experience
- Auto-approve low-risk operations based on conversation context + policy match
- Only prompt user for high-risk operations, showing full context (what, why, cost, scope)
- The crypto layer is invisible to users. They see "agent works smoothly" not "Ed25519 signatures"

### Why this specific market position
- Enterprise MCP security (Cerbos, Permit.io, Kong, Strata) won't come down to individual devs
- Claude Code sandbox doesn't extend to OpenClaw, Cursor, or other agents
- 1Password only covers browser credential injection
- Gap: lightweight, agent-agnostic, cryptographic authorization for local development

### Why OSS with acqui-hire exit
- Authorization middleware has no viable SaaS pricing model for individuals
- OSS builds community/stars → BigTech acquisition interest
- Potential acquirers: Anthropic (MCP ecosystem), 1Password (expand beyond browser), OpenAI (OpenClaw security)
- MIT license for acquisition ease

## Academic foundation

Primary: **South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025, arXiv:2501.09674)**
- Extends OAuth 2.0 / OpenID Connect for agent delegation
- 3-layer token structure: User ID + Agent ID + Delegation Token
- Natural language → structured permission translation via LLM
- VC migration path for multi-agent future

We simplify for local use:
- OIDC server → local Ed25519 keypairs
- JWT → lightweight signed JSON
- IdP federation → not needed (local only)

Supplementary:
- Rodriguez Garzon et al. "AI Agents with DIDs and VCs" (2025) — Phase 3 DID/VC patterns
- ERC-8004 "Trustless Agents" (2025) — Phase 3 on-chain compatibility

## Competitive landscape (as of Feb 2026)

| Layer | Players | signet's position |
|-------|---------|----------------------|
| MCP policy engines | Cerbos, Permit.io, Oso | Different layer (they do MCP; we do shell/fs/cred) |
| MCP gateways | Kong, Cloudflare, Runlayer | Enterprise; we target individual devs |
| Sandboxes | Claude Code (bubblewrap), ZeroClaw, NanoClaw, e2b, Daytona | Complementary (we add crypto auth on top) |
| Credential mgmt | 1Password (browser), Lit Protocol (on-chain) | We do local shell/CLI credential delegation |
| Agent identity | ERC-8004, LOKA Protocol | On-chain; we do local-first with future VC bridge |

MIT AI Agent Index 2025: Only 1 out of 30 surveyed agents uses cryptographic request signing. The gap is real.

## Implementation priorities

### Week 1: Core
1. `crypto/keys.ts` — Ed25519 keypair generation, storage, loading
2. `crypto/delegation.ts` — Delegation token create/verify
3. `policy/parser.ts` — YAML → Scope struct
4. `policy/matcher.ts` — Glob/pattern matching for fs, shell, network rules
5. `engine/evaluator.ts` — ActionRequest → ActionDecision (core loop)
6. `audit/logger.ts` — SQLite + chain hash logging

### Week 2: UX + Integration
7. CLI commands — init, activate, deactivate, log, check
8. `vault/manager.ts` — .env evacuation, credential isolation
9. `adapters/claude-code.ts` — settings.json + CLAUDE.md generation
10. `adapters/generic.ts` — PATH substitution wrapper
11. Templates — node.yml, python.yml, general.yml
12. README with demo GIF

### Phase 2 (post-launch)
- LLM-based natural language → structured permission auto-generation
- OpenClaw / Cursor adapters
- Slack/webhook approval flow

### Phase 3 (multi-agent)
- W3C DID/VC integration
- Agent-to-agent delegation chains
- ERC-8004 compatibility

## Developer context

Author: Kaz — Senior Software Developer at GovTech Tokyo
- Core skills: TypeScript/Node.js, React, Python, GCP
- Domain expertise: Digital Identity Wallet (DIW), government authentication/authorization, MCP architecture
- DevRel background: LINE/LY Corporation, React Native Japan (2,800+ members)
- This project connects GovTech DIW expertise with AI agent security — a rare intersection
