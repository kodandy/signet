# Sage vs signet: Detection vs Authorization for AI Agents

*Draft for Dev.to / Zenn*

---

On March 9, 2026, Gen Digital (Norton/Avast) announced **Sage** — an "Agentic Defense Runtime" that hooks into MCP tool calls to detect and block malware, phishing, and supply chain attacks. With 133 GitHub stars and 200+ detection rules, it's a serious tool solving a real problem.

But detection+block and authorization are different problems. Here's how they compare, and why you might want both.

## What Sage does

Sage is a TypeScript-based hook system that wraps MCP tool calls. It inspects every call against 200+ rules for:

- **Malware patterns**: file writes that look like dropper scripts
- **Phishing URLs**: links to credential harvesting sites
- **Supply chain attacks**: packages with known vulnerabilities or suspicious install scripts
- **Prompt injection**: attempts to manipulate agent behavior

Think of it as an **ADR (Agentic Defense Runtime)** — it detects threats and blocks them. It answers: **"Is this action safe?"**

## What signet does

signet sits between a user and their AI agent. It provides:

- **Cryptographic delegation**: Ed25519 keypairs for agents, signed tokens defining what they can do
- **Scoped authorization**: filesystem, network, shell, credential access with glob patterns
- **Credential isolation**: .env files encrypted and vaulted, injected per-command only when policy allows
- **Tamper-proof audit trail**: chain-hashed SQLite log of every request and decision

It answers: **"Is this agent authorized to do this?"**

## The key difference

| | Sage | signet |
|--|------|--------|
| Category | ADR (detection+block) | Authorization delegation |
| Question | "Is this safe?" | "Is this authorized?" |
| Approach | Hook-based rule matching (200+ rules) | Cryptographic delegation (Ed25519) |
| Scope | MCP tool calls | Shell, filesystem, network, credentials |
| Trust model | Blocklist (detect+block known threats) | Allowlist + signed delegation tokens |
| Credentials | Not handled | AES-256-GCM vault with per-command injection |
| Audit | Logs blocked actions | Chain-hashed log of all decisions (signed, tamper-proof) |
| Setup | SDK integration | `npm install -g ai-signet && signet init` |
| Language | TypeScript | TypeScript |

**Important clarification**: Sage is not "detection only" — it actively blocks threats. But it doesn't handle authorization delegation or credential management.

## Why you need both (defense in depth)

```
Layer 3: Detection+Block  → Sage (malware, phishing, supply chain)
Layer 2: Authorization     → signet (delegation, credentials, audit)
Layer 1: OS Sandbox        → nono / bubblewrap / Seatbelt (process isolation)
```

Sage catches things you didn't think to block. signet ensures agents only do what you explicitly allowed. nono prevents OS-level escapes.

Example scenario:

1. You delegate Claude Code to push to `origin/main` with `max_uses: 3`
2. Claude Code generates code that includes a dependency with a known vulnerability
3. **Sage** detects the vulnerable dependency and blocks the install
4. **signet** ensures Claude Code can't push more than 3 times, can't read `.env`, and every action is signed and logged
5. **nono** ensures the agent process can't escape its sandbox even if both Sage and signet are bypassed

Detection without authorization = you know it was caught, but you don't know what was allowed.
Authorization without detection = you control access, but you don't catch 0-day patterns.

## Technical comparison

### Sage's strength: Unknown threats

Sage uses 200+ rules (and likely ML models in future) to detect threats the user didn't anticipate. You don't need to write rules for every attack vector — Sage's rule engine handles it. Hook-based architecture means it integrates at the MCP layer.

### signet's strength: Explicit delegation with cryptographic proof

signet uses Ed25519 signatures to create a cryptographically verifiable chain of authorization. Every request is signed by the agent, every decision is signed by signet. The audit log is chain-hashed — if a single entry is modified, `signet log --verify` detects it.

This matters for:
- **Compliance**: Non-repudiable audit trail (SOC2, ISO27001)
- **Multi-agent**: Delegation chains (planned for Phase 3)
- **Credential safety**: Agents never see raw credentials — signet injects them per-command

## What about other tools?

| Tool | Layer | Relationship to signet |
|------|-------|----------------------|
| **nono** (1,100 stars) | OS sandbox (Seatbelt/Landlock) | Complementary: nono sandboxes processes, signet authorizes actions |
| **rampart** (52 stars) | YAML policy for MCP | Overlapping: similar policy concept, but no crypto, no vault, no audit |
| **clawdstrike** (245 stars) | Fleet security monitoring | Different scale: enterprise fleet tool, not for individual devs |
| **DeepSecure** (44 stars) | Docker+PG+Redis auth platform | Different complexity: heavy infra, Macaroon-based delegation |

## How to use both

```bash
# Install signet for authorization
npm install -g ai-signet
signet init --template node
signet activate

# Sage integration (when available)
# Sage inspects tool calls, signet handles credential/shell/fs authorization
# They operate at different layers — no conflict
```

## Conclusion

The AI agent security space is maturing rapidly. We're past "just trust the sandbox" and into specialized tools for specific threat models.

- Use **Sage** for detection+block: catch malware, phishing, supply chain attacks
- Use **signet** for authorization: control what agents can do, with cryptographic proof
- Use **nono** for OS-level isolation: prevent process escapes

They're complementary layers. Use all three.

---

*signet is open source (MIT). GitHub: https://github.com/kodandy/signet*
*Based on South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025)*
