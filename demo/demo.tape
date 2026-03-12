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

# ─── Setup: create alias so "signet" works ───
Hide
Type "alias signet='node $(pwd)/dist/index.js'"
Enter
Type "cd $(mktemp -d)"
Enter
Sleep 1s
Type "clear"
Enter
Sleep 500ms
Show

# ─── Title ───
Type "# signet — Your agent doesn't need your keys. It needs a keyhole."
Enter
Sleep 2s

# ─── 1. Initialize signet ───
Type "# 1. Initialize signet with a policy template"
Enter
Sleep 1s
Type "signet init --template node"
Enter
Sleep 3s

# ─── 2. Check status ───
Type "# 2. Check signet status"
Enter
Sleep 1s
Type "signet status"
Enter
Sleep 3s

# ─── 3. Activate vault protection ───
Type "# 3. Activate vault — isolate credentials from agents"
Enter
Sleep 1s
Type "signet activate"
Enter
Sleep 3s

# ─── 4. Dry-run policy checks ───
Type "# 4. Test what the agent can and cannot do"
Enter
Sleep 1s

Type 'signet check "npm test"'
Enter
Sleep 2s

Type 'signet check "rm -rf /"'
Enter
Sleep 2s

Type 'signet check "git push origin main"'
Enter
Sleep 3s

# ─── 5. View audit trail ───
Type "# 5. Tamper-proof audit trail with chain hashing"
Enter
Sleep 1s
Type "signet log -n 5"
Enter
Sleep 3s

# ─── 6. Verify integrity ───
Type "# 6. Verify audit chain integrity"
Enter
Sleep 1s
Type "signet log --verify"
Enter
Sleep 3s

# ─── 7. Deactivate vault ───
Type "# 7. Deactivate — restore credentials"
Enter
Sleep 1s
Type "signet deactivate"
Enter
Sleep 3s

# ─── Outro ───
Type "# Done. Cryptographic trust, not blind faith."
Enter
Sleep 3s
