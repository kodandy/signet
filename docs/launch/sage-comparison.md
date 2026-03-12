# Sage vs signet: Detection vs Authorization for AI Agents

*Draft for Dev.to / Zenn*

---

On March 9, 2026, Gen Digital (Norton/Avast) announced **Sage** — an "Agentic Defense Runtime" that intercepts AI agent tool calls to detect malware, phishing, and supply chain attacks. It's a real product solving a real problem.

But detection and authorization are different problems. Here's how they compare, and why you might want both.

## What Sage does

Sage sits between an AI agent and its tools (MCP servers, APIs). It inspects every tool call for:

- **Malware patterns**: file writes that look like dropper scripts
- **Phishing URLs**: links to credential harvesting sites
- **Supply chain attacks**: packages with known vulnerabilities or suspicious install scripts

Think of it as an antivirus for agent actions. It answers: **"Is this action safe?"**

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
| Question | "Is this safe?" | "Is this authorized?" |
| Approach | Detection (pattern matching) | Authorization (cryptographic delegation) |
| Scope | MCP tool calls | Shell, filesystem, network, credentials |
| Trust model | Blocklist | Allowlist + delegation tokens |
| Audit | Logs blocked actions | Chain-hashed log of all decisions (signed) |
| Setup | SDK integration | `npm install -g ai-signet && signet init` |
| Target | Agent framework developers | Individual developers using AI agents |

## Why you need both

Sage catches things you didn't think to block. signet ensures agents only do what you explicitly allowed.

Example scenario:

1. You delegate Claude Code to push to `origin/main` with `max_uses: 3`
2. Claude Code generates code that includes a dependency with a known vulnerability
3. **Sage** detects the vulnerable dependency and blocks the install
4. **signet** ensures Claude Code can't push more than 3 times, can't read `.env`, and every action is signed and logged

Detection without authorization = you know it was caught, but you don't know what was allowed.
Authorization without detection = you control access, but you don't catch 0-day patterns.

## Technical comparison

### Sage's strength: Unknown threats

Sage uses pattern matching (and likely ML models) to detect threats the user didn't anticipate. You don't need to write rules for every attack vector — Sage's models handle it.

### signet's strength: Explicit delegation

signet uses Ed25519 signatures to create a cryptographically verifiable chain of authorization. Every request is signed by the agent, every decision is signed by signet. The audit log is chain-hashed — if a single entry is modified, `signet log --verify` detects it.

This matters for:
- **Compliance**: Non-repudiable audit trail (SOC2, ISO27001)
- **Multi-agent**: Delegation chains (planned for Phase 3)
- **Credential safety**: Agents never see raw credentials — signet injects them per-command

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

The AI agent security space is maturing. We're past "just trust the sandbox" and into specialized tools for specific threat models.

- Use **Sage** for detection: catch malware, phishing, supply chain attacks
- Use **signet** for authorization: control what agents can do, with cryptographic proof

They're complementary. Use both.

---

*signet is open source (MIT). GitHub: https://github.com/kodandy/signet*
*Based on South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025)*
