import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";

const TEST_DIR = join(tmpdir(), `signet-demo-test-${Date.now()}`);
const SIGNET_HOME = join(TEST_DIR, ".signet");

// demo出力を一度だけ取得して全テストで共有
let demoOutput = "";
let demoExitCode = -1;

beforeAll(
  () => {
    mkdirSync(TEST_DIR, { recursive: true });
    try {
      demoOutput = execSync(
        `npx tsx ${join(process.cwd(), "src/index.ts")} demo`,
        {
          cwd: TEST_DIR,
          env: { ...process.env, HOME: TEST_DIR, SIGNET_DIR: SIGNET_HOME },
          encoding: "utf-8",
          timeout: 30000,
          stdio: ["pipe", "pipe", "pipe"],
        },
      );
      demoExitCode = 0;
    } catch (err: any) {
      demoOutput = err.stdout ?? "";
      demoExitCode = err.status ?? 1;
    }
  },
  30000, // demo takes ~8s due to wait() calls
);

afterAll(() => {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true, force: true });
  }
});

describe("signet demo", () => {
  test("runs to completion", () => {
    expect(demoExitCode).toBe(0);
    expect(demoOutput).toContain("signet demo");
  });

  test("shows all 5 steps", () => {
    expect(demoOutput).toContain("Step 1: Key Generation");
    expect(demoOutput).toContain("Step 2: Policy");
    expect(demoOutput).toContain("Step 3: Delegation Token");
    expect(demoOutput).toContain("Step 4: Agent Requests");
    expect(demoOutput).toContain("Step 5: Audit Trail");
  });

  test("generates keypairs and shows them", () => {
    expect(demoOutput).toContain("User  keypair:");
    expect(demoOutput).toContain("Agent keypair:");
    expect(demoOutput).toContain("Ed25519");
  });

  test("shows delegation token verification", () => {
    expect(demoOutput).toContain("Issuer:");
    expect(demoOutput).toContain("Subject:");
    expect(demoOutput).toContain("Expires:");
    expect(demoOutput).toContain("Max uses:");
    expect(demoOutput).toContain("Signature verified:");
  });

  test("evaluates all 7 scenarios", () => {
    expect(demoOutput).toContain("Agent writes to source file");
    expect(demoOutput).toContain("Agent tries to read .env");
    expect(demoOutput).toContain("Agent runs npm test");
    expect(demoOutput).toContain("Agent tries git push");
    expect(demoOutput).toContain("Agent tries rm -rf");
    expect(demoOutput).toContain("Agent connects to GitHub");
    expect(demoOutput).toContain("Agent connects to unknown host");
  });

  test("shows correct allow/deny decisions", () => {
    expect(demoOutput).toContain("fs_write");
    expect(demoOutput).toContain("allowed");
    expect(demoOutput).toContain("denied");
  });

  test("shows audit trail with chain hashes", () => {
    expect(demoOutput).toContain("chain:");
    expect(demoOutput).toContain("tamper");
  });

  test("shows summary and getting started", () => {
    expect(demoOutput).toContain("Summary");
    expect(demoOutput).toContain("Ed25519 keypairs generated");
    expect(demoOutput).toContain("tamper-evident");
    expect(demoOutput).toContain("npm install -g ai-signet");
    expect(demoOutput).toContain("signet init");
    expect(demoOutput).toContain("signet activate");
  });
});
