# Show HN Draft

## Title

Show HN: Signet – Cryptographic authorization for AI agents (Ed25519, no Docker, no SaaS)

## Body

I built signet because I was tired of the all-or-nothing trust model with AI coding agents.

**The problem**: Claude Code, Cursor, and other AI agents operate on your local machine with broad access. Current approaches are either sandboxes (static walls that can't express "use this credential 5 times for git push only") or enterprise policy engines (Docker + IdP + OAuth — nobody uses that locally).

**What signet does**: Treats AI agents as separate systems, like SSH treats remote machines.

- Every agent gets its own Ed25519 keypair
- You issue signed delegation tokens defining scope (filesystem, network, shell, credentials), expiration, max uses
- Every action request is signed, every approval is signed
- Tamper-proof audit trail via chain-hashed SQLite

```bash
npm install -g ai-signet
signet init --template node
signet activate
# Done. < 30 seconds.
```

Policy is a simple YAML file:

```yaml
scope:
  shell:
    deny: ["rm -rf *", "sudo *"]
    ask: ["git push *", "npm publish *"]
  filesystem:
    writable: ["./src/**"]
    blocked: ["./.env", "~/.ssh/**"]
  credentials:
    github_token:
      allowed_actions: ["git push"]
      max_uses: 10
```

Demo: [GIF in README]

**What this is NOT**: Not a sandbox. Not a policy engine. A cryptographic trust layer that produces non-repudiable audit logs.

**Academic foundation**: Based on South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025) [arXiv:2501.09674]. We simplify their OAuth/OIDC framework for local use: OIDC server → Ed25519 keypairs, JWT → signed JSON.

**Tech**: TypeScript, tweetnacl (Ed25519), better-sqlite3 (audit), ~29KB bundled. MIT licensed.

GitHub: https://github.com/kodandy/signet
npm: https://www.npmjs.com/package/ai-signet
