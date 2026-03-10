import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";
import { generateKeyPair, saveKeyPair, encodeBase64 } from "../src/crypto/keys";

const TEST_DIR = join(tmpdir(), `signet-cli-ux-test-${Date.now()}`);
const SIGNET_HOME = join(TEST_DIR, ".signet");

function runSignet(args: string, opts?: { cwd?: string }): { stdout: string; stderr: string; exitCode: number } {
  const cwd = opts?.cwd ?? TEST_DIR;
  try {
    const result = execSync(
      `npx tsx ${join(process.cwd(), "src/index.ts")} ${args}`,
      {
        cwd,
        env: { ...process.env, HOME: TEST_DIR, SIGNET_DIR: SIGNET_HOME },
        encoding: "utf-8",
        timeout: 10000,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    return { stdout: result, stderr: "", exitCode: 0 };
  } catch (err: any) {
    return {
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
      exitCode: err.status ?? 1,
    };
  }
}

beforeEach(() => {
  mkdirSync(TEST_DIR, { recursive: true });
});

afterEach(() => {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true, force: true });
  }
});

// ─── parseDuration tests (tested via delegate command) ───

describe("signet delegate", () => {
  test("errors when no user key exists", () => {
    const { stderr, exitCode } = runSignet("delegate AAAA");
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("User keypair not found");
  });

  test("errors when no signet.yml exists", () => {
    // Create user key but no signet.yml
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    const kp = generateKeyPair();
    saveKeyPair(kp, join(SIGNET_HOME, "user.key"));

    const { stderr, exitCode } = runSignet("delegate AAAA");
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("signet.yml not found");
  });

  test("issues a valid delegation token", () => {
    // Setup: user key + signet.yml
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    const userKey = generateKeyPair();
    saveKeyPair(userKey, join(SIGNET_HOME, "user.key"));

    const agentKey = generateKeyPair();
    const agentPubB64 = encodeBase64(agentKey.publicKey);

    const policyYml = `version: 1\nscope:\n  shell:\n    allow:\n      - "npm test"\n`;
    writeFileSync(join(TEST_DIR, "signet.yml"), policyYml);

    const { stdout, exitCode } = runSignet(`delegate ${agentPubB64}`);
    expect(exitCode).toBe(0);

    // stdout should be valid JSON token
    const token = JSON.parse(stdout.trim());
    expect(token.version).toBe(1);
    expect(token.subject).toBe(agentPubB64);
    expect(token.issuer).toBe(encodeBase64(userKey.publicKey));
    expect(token.signature).toBeDefined();
    expect(token.scope.shell.allow).toContain("npm test");
  });

  test("writes token to file with -o", () => {
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    const userKey = generateKeyPair();
    saveKeyPair(userKey, join(SIGNET_HOME, "user.key"));

    const agentKey = generateKeyPair();
    const agentPubB64 = encodeBase64(agentKey.publicKey);

    writeFileSync(join(TEST_DIR, "signet.yml"), `version: 1\nscope:\n  shell:\n    allow:\n      - "echo *"\n`);

    const outFile = join(TEST_DIR, "token.json");
    const { exitCode } = runSignet(`delegate ${agentPubB64} -o ${outFile}`);
    expect(exitCode).toBe(0);
    expect(existsSync(outFile)).toBe(true);

    const token = JSON.parse(readFileSync(outFile, "utf-8"));
    expect(token.subject).toBe(agentPubB64);
  });

  test("rejects invalid duration", () => {
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    const userKey = generateKeyPair();
    saveKeyPair(userKey, join(SIGNET_HOME, "user.key"));
    writeFileSync(join(TEST_DIR, "signet.yml"), `version: 1\nscope:\n  shell:\n    allow:\n      - "echo *"\n`);

    const agentKey = generateKeyPair();
    const agentPubB64 = encodeBase64(agentKey.publicKey);

    const { stderr, exitCode } = runSignet(`delegate ${agentPubB64} --expires nope`);
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("Invalid duration");
  });
});

// ─── signet check (expanded) ───

describe("signet check --type", () => {
  const policyYml = `version: 1
scope:
  shell:
    allow:
      - "npm test"
    deny:
      - "rm -rf *"
  filesystem:
    writable:
      - "./src/**"
    readable:
      - "./**"
    blocked:
      - "./.env"
  network:
    allow:
      - "github.com"
    deny:
      - "*"
  credentials:
    NPM_TOKEN:
      source: "env:NPM_TOKEN"
      require_approval: true
`;

  function setupPolicy() {
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    writeFileSync(join(TEST_DIR, "signet.yml"), policyYml);
  }

  test("shell check (default type)", () => {
    setupPolicy();
    const { stdout, exitCode } = runSignet('check "npm test"');
    expect(exitCode).toBe(0);
    expect(stdout).toContain("✅");
    expect(stdout).toContain("allow");
  });

  test("fs_write check", () => {
    setupPolicy();
    const { stdout, exitCode } = runSignet('check "./src/foo.ts" --type fs_write');
    expect(exitCode).toBe(0);
    expect(stdout).toContain("✅");
    expect(stdout).toContain("allow");
  });

  test("fs_write blocked check", () => {
    setupPolicy();
    const { stdout, exitCode } = runSignet('check "./.env" --type fs_write');
    expect(exitCode).toBe(0);
    expect(stdout).toContain("❌");
    expect(stdout).toContain("deny");
  });

  test("network check", () => {
    setupPolicy();
    const { stdout, exitCode } = runSignet('check "github.com" --type network');
    expect(exitCode).toBe(0);
    expect(stdout).toContain("✅");
  });

  test("network deny check", () => {
    setupPolicy();
    const { stdout, exitCode } = runSignet('check "evil.com" --type network');
    expect(exitCode).toBe(0);
    expect(stdout).toContain("❌");
  });

  test("credential check", () => {
    setupPolicy();
    const { stdout, exitCode } = runSignet('check "NPM_TOKEN" --type credential');
    expect(exitCode).toBe(0);
    expect(stdout).toContain("❓");
    expect(stdout).toContain("ask");
  });

  test("unknown type errors", () => {
    setupPolicy();
    const { stderr, exitCode } = runSignet('check "foo" --type invalid');
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("Unknown type");
  });
});

// ─── signet status ───

describe("signet status", () => {
  test("shows checklist with nothing configured", () => {
    const { stdout, exitCode } = runSignet("status");
    expect(exitCode).toBe(0);
    expect(stdout).toContain("❌");
    expect(stdout).toContain("signet init");
  });

  test("shows key configured after init", () => {
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    const kp = generateKeyPair();
    saveKeyPair(kp, join(SIGNET_HOME, "user.key"));
    writeFileSync(join(TEST_DIR, "signet.yml"), `version: 1\nscope:\n  shell:\n    allow:\n      - "echo *"\n`);

    const { stdout, exitCode } = runSignet("status");
    expect(exitCode).toBe(0);
    expect(stdout).toContain("✅");
    expect(stdout).toContain("configured");
    expect(stdout).toContain("Public key:");
    expect(stdout).toContain("shell");
  });
});

// ─── signet keys register ───

describe("signet keys register", () => {
  test("registers an agent key", () => {
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    const agentKey = generateKeyPair();
    const agentPubB64 = encodeBase64(agentKey.publicKey);

    const { stdout, exitCode } = runSignet(`keys register my-agent ${agentPubB64}`);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("Registered agent key: my-agent");

    // Verify file was written
    const keyPath = join(SIGNET_HOME, "agents", "my-agent.pub");
    expect(existsSync(keyPath)).toBe(true);
  });

  test("rejects duplicate registration", () => {
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    const agentKey = generateKeyPair();
    const agentPubB64 = encodeBase64(agentKey.publicKey);

    // Pre-create the agent key file directly instead of running CLI twice
    const agentsDir = join(SIGNET_HOME, "agents");
    mkdirSync(agentsDir, { recursive: true, mode: 0o700 });
    writeFileSync(join(agentsDir, "dup-agent.pub"), agentPubB64 + "\n");

    const { stderr, exitCode } = runSignet(`keys register dup-agent ${agentPubB64}`);
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("already registered");
  });

  test("rejects invalid pubkey", () => {
    mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
    const { stderr, exitCode } = runSignet('keys register bad-agent "not-valid-base64!!!"');
    expect(exitCode).not.toBe(0);
  });
});
