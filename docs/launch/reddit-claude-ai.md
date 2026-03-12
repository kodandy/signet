# r/ClaudeAI Post Draft

## Title

I built a cryptographic authorization layer for Claude Code (so it can use your credentials without seeing them)

## Body

Every time Claude Code needs to `git push`, it either has your token or it doesn't work. Every time it reads a file, it can see your `.env`. The sandbox helps, but it's binary — all or nothing.

I built **signet** to fix this.

**What it does:**
- Agents get their own Ed25519 keypair (separate identity, like SSH)
- You define what they can do in a YAML policy: which commands, which files, which credentials, for how long
- Credentials are encrypted and vaulted — agents never see raw tokens. signet injects them per-command when policy allows
- Every action is cryptographically signed. Tamper-proof audit log

**30-second setup:**

```bash
npm install -g ai-signet
signet init --template node
signet activate
```

**Example policy:**

```yaml
scope:
  shell:
    deny: ["rm -rf *", "sudo *"]
    ask: ["git push *", "npm publish *"]
  filesystem:
    blocked: ["./.env", "~/.ssh/**", "~/.aws/**"]
  credentials:
    github_token:
      allowed_actions: ["git push"]
      max_uses: 10
```

Now Claude Code can `git push` up to 10 times using your GitHub token — without ever seeing the token itself.

**Not a replacement for the sandbox.** signet adds a cryptographic layer on top. The sandbox controls access; signet controls authorization with signed delegation tokens.

Open source (MIT): https://github.com/kodandy/signet

Based on MIT research: South et al. "Authenticated Delegation and Authorized AI Agents" (2025)

Would love feedback from other Claude Code users. What credential/permission scenarios bother you most?
