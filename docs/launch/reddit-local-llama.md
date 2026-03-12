# r/LocalLLaMA Post Draft

## Title

Open-source cryptographic trust layer for local AI agents — Ed25519 signatures, no cloud, works with any agent

## Body

Built an open-source tool for anyone running AI coding agents locally (Claude Code, OpenClaw, Cursor, or any CLI agent).

**Problem:** AI agents run on your machine with broad access. Sandboxes are static walls. Enterprise auth tools (Cerbos, Auth0) require Docker + IdP + OAuth. Nothing exists for individual developers who want cryptographic authorization locally.

**signet** fills this gap:

- **Ed25519 keypairs** for each agent (separate cryptographic identity)
- **Signed delegation tokens** with scope (filesystem, network, shell, credentials), expiration, max uses
- **Credential vault**: .env files encrypted with AES-256-GCM, injected per-command only when policy allows
- **Chain-hashed audit trail**: tamper-evident SQLite log. If any entry is modified, `signet log --verify` detects it
- **Agent-agnostic**: works with Claude Code, OpenClaw, Cursor, or any CLI tool via PATH wrapper

```bash
npm install -g ai-signet
signet init --template node
signet activate
```

**No cloud. No SaaS. No phone-home. Everything stays local.**

Policy is a simple YAML:

```yaml
scope:
  shell:
    deny: ["rm -rf *", "sudo *"]
    ask: ["git push *"]
  filesystem:
    writable: ["./src/**"]
    blocked: ["./.env", "~/.ssh/**"]
```

~29KB bundled. Minimal deps (tweetnacl, better-sqlite3, commander, yaml). MIT licensed.

Based on South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025) — simplifies their OAuth/OIDC framework for local use.

GitHub: https://github.com/kodandy/signet

Looking for feedback, especially from people running local agents. What access control scenarios matter most to you?
