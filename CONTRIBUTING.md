# Contributing to signet

## Setup

```bash
# Clone
git clone https://github.com/anthropics/signet.git
cd signet

# Install dependencies
npm install

# Run tests
npm test
```

Requires Node.js 20+ or Bun 1.0+.

## Project Structure

```
src/
  crypto/       — Ed25519 keypair management + delegation tokens
  policy/       — YAML parser + glob/pattern matching
  engine/       — Core evaluation loop
  vault/        — Credential isolation (.env evacuation)
  audit/        — SQLite logger with chain hashing
  adapters/     — Claude Code, generic (PATH wrapper)
  index.ts      — CLI entry point
templates/      — Preset policy files
test/           — Tests per module
```

## Development

- Runtime: Bun (with Node.js compatibility for npm distribution)
- Tests: `vitest` (`npm test`)
- Type-first: define interfaces before implementation
- Prefer functions + interfaces over classes
- All crypto operations are synchronous (tweetnacl is sync)
- Minimal dependencies — avoid adding new ones unless necessary

## Testing

Every public function needs a test. Tests live in `test/` and follow the naming convention `<module>.test.ts`.

```bash
# Run all tests
npm test

# Run a specific test file
npx vitest run test/crypto-keys.test.ts
```

## Pull Requests

1. Fork and create a feature branch
2. Make your changes
3. Add/update tests
4. Run `npm test` and ensure all tests pass
5. Submit a PR with a clear description of the change

Keep PRs focused — one feature or fix per PR.

## Good First Issues

Look for issues labeled `good first issue`. Some areas where contributions are welcome:

- **Adapters**: Cursor, Windsurf, Aider, OpenClaw
- **Policy templates**: Django, Rails, Go, Rust, etc.
- **Documentation**: Tutorials, examples, translations

## Code Style

- Error messages in English
- Code comments in English or Japanese
- No unnecessary abstractions — three similar lines > premature helper function
- Keep diffs minimal — don't reformat unrelated code

## Security

If you find a security vulnerability, please report it privately rather than opening a public issue. Email the maintainers or use GitHub's security advisory feature.
