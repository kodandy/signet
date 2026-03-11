# signet — Cryptographic authorization delegation for AI agents
# VHS demo tape: https://github.com/charmbracelet/vhs

Output demo/signet-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 600
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20

# ─── Title ───
Type "# signet — Your agent doesn't need your keys. It needs a keyhole."
Enter
Sleep 2s

# ─── 1. Initialize signet ───
Type "# 1. Initialize signet with smart project detection"
Enter
Sleep 1s
Type "signet init --smart"
Enter
Sleep 3s

# ─── 2. Check status ───
Type "# 2. Check signet status"
Enter
Sleep 1s
Type "signet status"
Enter
Sleep 3s

# ─── 3. Scan for exposed credentials ───
Type "# 3. Scan project for credential leaks"
Enter
Sleep 1s
Type "signet scan"
Enter
Sleep 3s

# ─── 4. Generate agent keypair ───
Type "# 4. Generate an Ed25519 keypair for Claude Code"
Enter
Sleep 1s
Type "signet keys generate claude-code"
Enter
Sleep 3s

# ─── 5. Delegate authority ───
Type "# 5. Issue a scoped delegation token (expires in 2h)"
Enter
Sleep 1s
Type "signet delegate $(cat ~/.signet/agents/claude-code.pub) --expires 2h"
Enter
Sleep 3s

# ─── 6. Dry-run policy checks ───
Type "# 6. Test what the agent can and cannot do"
Enter
Sleep 1s

Type 'signet check "npm test"'
Enter
Sleep 2s

Type 'signet check "rm -rf /"'
Enter
Sleep 2s

Type 'signet check --type fs_write ./src/index.ts'
Enter
Sleep 2s

Type 'signet check --type network api.github.com'
Enter
Sleep 3s

# ─── 7. View audit trail ───
Type "# 7. Tamper-proof audit trail with chain hashing"
Enter
Sleep 1s
Type "signet log -n 5"
Enter
Sleep 3s

# ─── 8. Verify integrity ───
Type "# 8. Verify audit chain integrity"
Enter
Sleep 1s
Type "signet log --verify"
Enter
Sleep 3s

# ─── Outro ───
Type "# Done. Cryptographic trust, not blind faith."
Enter
Sleep 3s
