# signet: Go-To-Market Strategy

Last updated: 2026-03-16

## Market Position

```
Enterprise / SaaS / Cloud API  ← Cerbos, Permit.io, Auth0, Nango, Arcade
              ↕ GAP
Local / OSS / Shell+FS+Cred    ← signet (ONLY PLAYER)
```

Individual developers using AI agents (Claude Code, OpenClaw, Cursor) locally have no cryptographic authorization layer. Enterprise tools won't come down to this segment. signet fills this gap.

### Tagline

> "Your agent doesn't need your keys. It needs a keyhole."

### One-liner

Cryptographic authorization delegation for local AI agents. Ed25519 signatures, credential isolation, tamper-proof audit — in a single `npm install ai-signet`.

## Market Timing (as of March 2026)

### Tailwinds

- **NIST** released "AI Agent Identity & Authorization" concept paper (Feb 2026), seeking public input
- **IETF** published AI-Auth draft (draft-klrc-aiagent-auth) for OAuth 2.0-based agent authorization
- **OWASP** released "Top 10 for Agentic Applications 2026" with 100+ expert reviewers
- **MIT AI Agent Index 2025**: Only 1/30 surveyed agents uses cryptographic request signing
- Anthropic shipped Claude Code Security (vulnerability scanning) — authorization is the obvious next step
- OpenAI shipped Codex Security (Mar 6, 2026) — no authorization component

### Competitive Landscape (updated 2026-03-16)

#### Tier 1: Direct competitors (local agent security)

| Tool | Stars | What it does | signet's edge |
|------|-------|-------------|---------------|
| **Sage** (Gen Digital) | 133 | ADR: hook-based detection+block for MCP tool calls. 200+ rules, TypeScript | Sage = detection+block (ADR), not authorization. No delegation tokens, no credential vault, no audit chain. Complementary |
| **nono** | 1,100 | Kernel sandbox (Seatbelt/Landlock) for AI agents. Rust | OS-level isolation, not authorization. No credential delegation, no policy language. Complementary — nono sandboxes, signet authorizes |
| **rampart** | 52 | YAML policy firewall for MCP tools. Go | Closest simple competitor. But no crypto signatures, no credential vault, no audit chain. Policy-only |
| **cupcake** | 8 | OPA/Rego-based MCP policy engine | Heavyweight (OPA dependency). No crypto, no vault. Enterprise-oriented policy |

#### Tier 2: Enterprise / infrastructure-tier

| Tool | Stars | What it does | signet's edge |
|------|-------|-------------|---------------|
| **clawdstrike** | 245 | Ed25519 verdict signing, fleet security monitoring. TypeScript | Enterprise fleet tool. Requires infrastructure. Not for individual devs |
| **DeepSecure** | 44 | Docker+PostgreSQL+Redis auth platform. Macaroon delegation. Python | Heavy infrastructure. Not `npm install` simple. Different audience |
| **agent-passport-system** | 5 | Ed25519 delegation tokens. TypeScript | Conceptually closest. But no vault, no audit chain, not production-ready |

#### Tier 3: Platform / API-level (different category)

| Tool | What it does | signet's edge |
|------|-------------|---------------|
| **Cerbos** | OSS YAML policy engine (PDP) | Microservices-focused. No local agent support, no credential isolation |
| **Arcade** | OSS OAuth permission checker for agent tool calls | API/OAuth only. No shell/fs/credential scope |
| **Nango** | OSS OAuth broker for 700+ APIs | Cloud API integration. No local credentials |
| **Auth0 for AI Agents** | Enterprise OAuth for agent delegation | Enterprise pricing. No local-first story |
| **1Password Agentic** | Browser credential autofill for agents | Browser-only. No CLI/shell injection |
| **Claude Code sandbox** | bubblewrap/seatbelt directory & domain allow/deny | Static walls. Can't express conditional credential delegation |

### signet's Unique Combination

**No existing tool combines all four properties simultaneously:**

| Property | signet | Sage | nono | rampart | clawdstrike | DeepSecure | agent-passport |
|----------|--------|------|------|---------|-------------|------------|----------------|
| Ed25519 delegation tokens | YES | — | — | — | YES (verdicts only) | Macaroon | YES |
| Credential vault | YES | — | — | — | — | — | — |
| Chain-hashed audit | YES | — | — | — | — | — | — |
| Zero infrastructure | YES | YES | YES | YES | — | — | YES |

1. **Cryptographic signing** (Ed25519) for every request/decision
2. **Credential isolation** (AES-256-GCM vault with per-command injection)
3. **Tamper-proof audit** (chain-hashed SQLite)
4. **Zero infrastructure** (no server, no Docker, no SaaS — just `npm install`)

Plus: shell/filesystem/credential scope (not just MCP/API), agent-agnostic (Claude Code, OpenClaw, Cursor, any CLI)

### Complementary Stack Story

signet is not a replacement for sandbox or detection tools — it's the missing authorization layer:

```
Layer 3: Detection+Block  → Sage (malware, phishing, supply chain)
Layer 2: Authorization     → signet (delegation, credentials, audit)
Layer 1: OS Sandbox        → nono / bubblewrap / Seatbelt (process isolation)
```

This "defense in depth" narrative positions signet without competing with the highest-star tools.

## Target Users

### Primary: Individual developers using AI coding agents

- Use Claude Code, Cursor, or OpenClaw daily
- Have `.env` files with API keys, database URLs, cloud credentials
- Feel uneasy about agent access but don't want to slow down
- Won't adopt enterprise tools (too heavy, too expensive)

### Secondary: Security-conscious teams (2-10 devs)

- Need audit trail for compliance (SOC2, ISO27001)
- Want per-developer agent policies
- Currently rely on "trust the sandbox" with no visibility

### Tertiary: AI agent framework developers

- Building agents that need credential access
- Want to offer "secure by default" to their users
- Integration via signet SDK / MCP tool

## Phase 1: Mindshare (Week 1-2 post-launch)

### 1.1 Demo-First Launch

The demo GIF is the most important asset. Before writing blog posts or documentation, create:

```
15-second GIF showing:
1. Claude Code tries to read .env → signet blocks it
2. Claude Code requests git push → signet asks user → approved
3. Audit log shows signed, chain-hashed record

This GIF goes in: README hero section, HN post, Reddit posts, tweets
```

Additionally, ship an interactive demo:

```bash
npx ai-signet demo
# Walks through a simulated agent session without requiring Claude Code
# Shows: key generation → delegation → request → policy check → audit
```

### 1.2 Launch Channels (Priority Order)

| Channel | Priority | Timing | Why |
|---------|----------|--------|-----|
| **Hacker News (Show HN)** | Highest | Day 1 | Crypto + security + OSS = HN audience. Academic foundation (MIT paper) adds credibility |
| **r/ClaudeAI** | High | Day 1 | Users experiencing permission fatigue daily. Direct pain point |
| **r/LocalLLaMA** | High | Day 1-2 | Values local-first, OSS, privacy. Natural alignment |
| **X (Twitter)** | High | Day 1+ | AI developer discourse. Anthropic employees are watching |
| **Dev.to** | Medium | Week 1 | Technical deep-dive article. SEO value |
| **Zenn** | Medium | Week 1 | Japanese developer community. Author's existing network |
| **Product Hunt** | Low | Skip | Not effective for developer CLI tools |

### 1.3 HN Post Strategy

**Title:**
```
Show HN: Signet – Cryptographic authorization for AI agents (no Docker, no SaaS, just Ed25519)
```

**What resonates on HN:**
- Academic foundation (MIT paper: South et al. 2025)
- Correct cryptography (Ed25519, chain hashing — not homebrew crypto)
- Anti-enterprise positioning (`npm install ai-signet`, not Docker + IdP + OAuth)
- Small, auditable codebase (tweetnacl + better-sqlite3, minimal deps)

**What to avoid:**
- "AI Security Platform" or any grandiose framing
- Mentioning star counts or download numbers
- Comparing to enterprise tools as competitors (position as different category)

### 1.4 Reddit Strategy

**r/ClaudeAI post:**
```
Title: "I built a cryptographic authorization layer for Claude Code
       (so it can use your credentials without seeing them)"

Body: Focus on the pain:
- "Every time Claude Code needs to git push, it either has your token or it doesn't work"
- "signet lets you issue signed, time-limited, scope-limited delegation tokens"
- Demo GIF
- `npm install -g ai-signet && signet init`
```

**r/LocalLLaMA post:**
```
Title: "Open-source cryptographic trust layer for local AI agents
       — works with any agent, not just Claude"

Body: Focus on local-first + agent-agnostic:
- No cloud, no SaaS, no phone-home
- Ed25519 keypairs stored locally
- Works with Claude Code, OpenClaw, Cursor, or any CLI tool
- MIT licensed
```

## Phase 2: Community Building (Month 1-2)

### 2.1 Content Strategy

**Article 1: The Fear Post (viral potential)**
```
"I let Claude Code run for 24 hours. Here's every secret it could have accessed."

- Log all .env, ~/.ssh, ~/.aws/credentials, ~/.npmrc access attempts
- Show what the sandbox catches vs. what it doesn't
- Before/after with signet
- Publish on: Dev.to, personal blog, cross-post to HN
```

**Article 2: Sage Comparison (ride the wave)**
```
"Sage vs signet: Detection vs Authorization for AI Agents"

- Sage (Gen Digital, Mar 2026): blocks malware, phishing, supply chain attacks
- signet: cryptographic delegation, credential isolation, audit trail
- Not competing — complementary. Use both.
- Show: Sage + signet working together
- Publish within 1 week of launch (while Sage attention is fresh)
```

**Article 3: The Technical Deep-Dive**
```
"Implementing MIT's Authenticated Delegation paper for local AI agents"

- Walk through South et al. (arXiv:2501.09674)
- How signet simplifies: OIDC → Ed25519, JWT → signed JSON, IdP → local keypairs
- Code examples from actual implementation
- Target: HN, academic Twitter, security researchers
```

### 2.2 Reduce Friction

Templates are critical. No one should write YAML policies from scratch:

```bash
signet init --template node      # Node.js preset
signet init --template python    # Python preset
signet init --template general   # Generic preset
```

Each template includes:
- Sensible defaults (block .env, allow src/**, ask for git push)
- Comments explaining each rule
- Link to full policy reference

Target: **< 30 seconds from install to working protection**.

```bash
npm install -g ai-signet
signet init --template node
signet activate
# Done. Agent is now running under signet.
```

### 2.3 GitHub Community

- **Good First Issues**: Label easy tasks for contributors
- **CONTRIBUTING.md**: Clear setup instructions, PR process
- **Adapter Bounties**: Encourage community-built adapters (Cursor, Windsurf, Aider)
- **Policy Template Contributions**: Accept community YAML templates for frameworks (Django, Rails, etc.)

## Phase 3: Strategic Positioning (Month 2-3)

### 3.1 Primary Target: Anthropic

**Why Anthropic:**
- Claude Code's MCP ecosystem lacks an authorization layer
- They shipped Claude Code Security (vulnerability scanning) — authorization is the next logical step
- NIST standardization will push them to formalize agent auth
- signet's Claude Code adapter makes integration natural

**Approach:**

```
Step 1: Ship the best Claude Code experience
        → settings.json auto-generation
        → CLAUDE.md policy injection
        → "Claude Code + signet" must be the smoothest combination

Step 2: Build visibility with Anthropic employees on X
        → Technical, correct posts about agent authorization
        → Engage with Anthropic's security/MCP announcements
        → Target: Developer Relations, MCP team, Trust & Safety

Step 3: Apply for MCP official directory listing
        → Package signet as an MCP tool
        → Submit to Anthropic's MCP registry

Step 4: Propose integration
        → "Claude Code Security (detection) + signet (authorization)"
        → Concrete technical proposal, not a pitch deck
```

### 3.2 Secondary Targets

**1Password:**
- Their Agentic Autofill is browser-only
- signet's vault fills the CLI/shell gap
- Pitch: "1Password for the terminal, but cryptographically delegated"

**OpenAI:**
- Codex Security (Mar 6, 2026) has no authorization component
- OpenClaw has no credential isolation
- signet's generic adapter already works with OpenClaw

### 3.3 Standards Alignment

- Monitor NIST AI Agent Identity & Authorization (comments due Apr 2, 2026)
- Track IETF AI-Auth draft evolution
- Consider: should signet adopt OAuth 2.0 token format for NIST compatibility?
- Phase 3 DID/VC bridge aligns with W3C direction

## Metrics & Milestones

| Metric | Month 1 | Month 3 | Month 6 |
|--------|---------|---------|---------|
| GitHub Stars | 500+ | 2,000+ | 5,000+ |
| npm weekly downloads | 200+ | 1,000+ | 5,000+ |
| Contributors | 3+ | 10+ | 20+ |
| HN front page | 1x | 2x | — |
| Anthropic employee awareness | — | Confirmed | Conversation |
| Adapters shipped | 2 (Claude Code, generic) | 4 (+OpenClaw, Cursor) | 6+ |
| Policy templates | 3 | 10+ | 20+ |

## Risks & Mitigations

### Risk 1: nono (1,100 stars) or Sage (133 stars) captures "local agent security" mindshare
- **Mitigation**: Position as complementary layer, not competing. nono = OS sandbox, Sage = detection, signet = authorization. Publish "defense in depth" article showing all three together. The 3-layer narrative benefits all tools.

### Risk 2: Anthropic builds native authorization into Claude Code
- **Mitigation**: Ship Claude Code adapter first. Make signet the obvious acquisition target. Agent-agnostic positioning means signet survives even if Claude Code goes native.

### Risk 3: NIST standardization makes custom signing format obsolete
- **Mitigation**: Track NIST closely. Plan OAuth 2.0 / OIDC token format as Phase 2 option. The core concepts (delegation, audit, credential isolation) are format-agnostic.

### Risk 4: Low adoption due to setup friction
- **Mitigation**: Templates, `npx ai-signet demo`, < 30 second setup. If it takes more than a minute, it's a bug.

### Risk 5: "Security tool by unknown developer" trust problem
- **Mitigation**: MIT paper foundation, minimal auditable codebase, transparent crypto (tweetnacl is well-vetted), MIT license. Invite security audits from community.

## Immediate Action Items

```
Priority 1 (This week):
  □ Complete MVP (crypto + policy + engine + audit)
  □ Create 15-second demo GIF
  □ Write README: demo → install → 30-second quickstart
  □ Build `npx ai-signet demo` interactive experience

Priority 2 (Launch week):
  □ Post Show HN
  □ Post r/ClaudeAI + r/LocalLLaMA
  □ Tweet thread with demo GIF
  □ Publish Sage comparison article

Priority 3 (Post-launch):
  □ "24-hour agent audit" fear post
  □ Technical deep-dive (MIT paper implementation)
  □ Good First Issues for contributors
  □ MCP directory application
```

## Exit Strategy

Per CONTEXT.md: OSS with acqui-hire exit.

- Authorization middleware has no viable SaaS pricing for individuals
- OSS builds community + stars → acquisition interest
- Primary: Anthropic (MCP ecosystem, Claude Code integration)
- Secondary: 1Password (expand beyond browser), OpenAI (OpenClaw security)
- MIT license for acquisition ease
