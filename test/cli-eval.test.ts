import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync, spawnSync, exec } from "node:child_process";
import { promisify } from "node:util";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { generateKeyPair, saveKeyPair, encodeBase64, type KeyPair } from "../src/crypto/keys";
import { createDelegation } from "../src/crypto/delegation";
import { parsePolicy } from "../src/policy/parser";
import { AuditLogger, type AuditEntry } from "../src/audit/logger";
import { generateWrappers } from "../src/adapters/generic";

const TEST_DIR = join(tmpdir(), `signet-cli-eval-test-${Date.now()}`);
const SIGNET_HOME = join(TEST_DIR, ".signet");
const AUDIT_DB = join(SIGNET_HOME, "audit.db");
const TOKEN_PATH = join(TEST_DIR, "token.json");

const POLICY_YML = `version: 1
scope:
  shell:
    allow:
      - "npm test"
    deny:
      - "rm -rf *"
    ask:
      - "git push *"
`;

function runSignet(
  args: string,
  env: Record<string, string> = {},
): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execSync(`npx tsx ${join(process.cwd(), "src/index.ts")} ${args}`, {
      cwd: TEST_DIR,
      env: { ...process.env, HOME: TEST_DIR, SIGNET_AGENT: "", SIGNET_TOKEN: "", ...env },
      encoding: "utf-8",
      timeout: 20000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? "", stderr: e.stderr ?? "", exitCode: e.status ?? 1 };
  }
}

function readAudit(): { entries: AuditEntry[]; chainValid: boolean } {
  if (!existsSync(AUDIT_DB)) return { entries: [], chainValid: true };
  const logger = new AuditLogger(AUDIT_DB);
  const entries = logger.getEntries();
  const chainValid = logger.verify().valid;
  logger.close();
  return { entries, chainValid };
}

function setupAgent(
  name: string,
  userKey: KeyPair,
  policyYml: string = POLICY_YML,
  delegationOpts?: Parameters<typeof createDelegation>[3],
): KeyPair {
  const agentsDir = join(SIGNET_HOME, "agents");
  mkdirSync(agentsDir, { recursive: true, mode: 0o700 });
  const agentKey = generateKeyPair();
  saveKeyPair(agentKey, join(agentsDir, `${name}.key`));
  writeFileSync(join(agentsDir, `${name}.pub`), encodeBase64(agentKey.publicKey) + "\n");
  const token = createDelegation(
    userKey,
    encodeBase64(agentKey.publicKey),
    parsePolicy(policyYml).scope,
    delegationOpts,
  );
  writeFileSync(TOKEN_PATH, JSON.stringify(token), { mode: 0o600 });
  return agentKey;
}

let userKey: KeyPair;

beforeEach(() => {
  mkdirSync(SIGNET_HOME, { recursive: true, mode: 0o700 });
  writeFileSync(join(TEST_DIR, "signet.yml"), POLICY_YML);
  userKey = generateKeyPair();
  saveKeyPair(userKey, join(SIGNET_HOME, "user.key"));
});

afterEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
});

describe("signet eval", () => {
  test("allowed command exits 0 and writes one signed audit entry", () => {
    const agentKey = setupAgent("bot", userKey);

    const { stdout, exitCode } = runSignet(`eval "npm test" --agent bot --token ${TOKEN_PATH}`);

    const { entries, chainValid } = readAudit();
    expect(exitCode).toBe(0);
    expect(stdout).toContain("allow");
    expect(entries.length).toBe(1);
    expect(entries[0].request.action).toBe("shell");
    expect(entries[0].request.target).toBe("npm test");
    expect(entries[0].request.agent_id).toBe(encodeBase64(agentKey.publicKey));
    expect(entries[0].decision.allowed).toBe(true);
    expect(entries[0].decision.decided_by).toBe("policy");
    expect(chainValid).toBe(true);
  });

  test("denied command exits 1 and the denial is logged", () => {
    setupAgent("bot", userKey);

    const { stdout, exitCode } = runSignet(`eval "rm -rf /" --agent bot --token ${TOKEN_PATH}`);

    const { entries } = readAudit();
    expect(exitCode).toBe(1);
    expect(stdout).toContain("deny");
    expect(entries.length).toBe(1);
    expect(entries[0].decision.allowed).toBe(false);
    expect(entries[0].decision.reason).toContain("Denied by policy");
  });

  test("ask rule without a terminal is denied and logged", () => {
    setupAgent("bot", userKey);

    const { exitCode } = runSignet(`eval "git push origin main" --agent bot --token ${TOKEN_PATH}`);

    const { entries } = readAudit();
    expect(exitCode).toBe(1);
    expect(entries.length).toBe(1);
    expect(entries[0].decision.allowed).toBe(false);
    expect(entries[0].decision.reason).toContain("Requires user approval");
  });

  test("two evaluations form a valid hash chain", () => {
    setupAgent("bot", userKey);

    runSignet(`eval "npm test" --agent bot --token ${TOKEN_PATH}`);
    runSignet(`eval "rm -rf /" --agent bot --token ${TOKEN_PATH}`);

    const { entries, chainValid } = readAudit();
    expect(entries.length).toBe(2);
    expect(entries[0].previous_hash).toBe(entries[1].chain_hash);
    expect(chainValid).toBe(true);
  });

  test("agent and token are read from SIGNET_AGENT / SIGNET_TOKEN", () => {
    setupAgent("bot", userKey);

    const { exitCode } = runSignet(`eval "npm test"`, {
      SIGNET_AGENT: "bot",
      SIGNET_TOKEN: TOKEN_PATH,
    });

    expect(exitCode).toBe(0);
    expect(readAudit().entries.length).toBe(1);
  });

  test("token issued to another agent is denied and logged", () => {
    setupAgent("bot", userKey);
    const otherKey = generateKeyPair();
    saveKeyPair(otherKey, join(SIGNET_HOME, "agents", "other.key"));

    const { exitCode } = runSignet(`eval "npm test" --agent other --token ${TOKEN_PATH}`);

    const { entries } = readAudit();
    expect(exitCode).toBe(1);
    expect(entries.length).toBe(1);
    expect(entries[0].decision.reason).toBe("Agent not authorized by delegation token");
  });

  test("missing agent exits 2 with a setup hint and logs nothing", () => {
    setupAgent("bot", userKey);

    const { stderr, exitCode } = runSignet(`eval "npm test" --token ${TOKEN_PATH}`);

    expect(exitCode).toBe(2);
    expect(stderr).toContain("--agent");
    expect(readAudit().entries.length).toBe(0);
  });

  test("unreadable token file exits 2", () => {
    setupAgent("bot", userKey);

    const { stderr, exitCode } = runSignet(
      `eval "npm test" --agent bot --token ${join(TEST_DIR, "missing.json")}`,
    );

    expect(exitCode).toBe(2);
    expect(stderr).toContain("token");
  });

  test("agent name with a path separator is rejected", () => {
    setupAgent("bot", userKey);

    const { stderr, exitCode } = runSignet(`eval "npm test" --agent ../user --token ${TOKEN_PATH}`);

    expect(exitCode).toBe(2);
    expect(stderr).toContain("Invalid agent name");
    expect(readAudit().entries.length).toBe(0);
  });
});

describe("signet eval: the signed token is the policy", () => {
  test("a permissive signet.yml in the working directory does not widen the token's scope", () => {
    setupAgent("bot", userKey);
    writeFileSync(join(TEST_DIR, "signet.yml"), `version: 1\nscope:\n  shell:\n    allow:\n      - "*"\n`);

    const { exitCode } = runSignet(`eval "rm -rf /" --agent bot --token ${TOKEN_PATH}`);

    const { entries } = readAudit();
    expect(exitCode).toBe(1);
    expect(entries.length).toBe(1);
    expect(entries[0].decision.allowed).toBe(false);
  });

  test("evaluates without a signet.yml in the working directory", () => {
    setupAgent("bot", userKey);
    rmSync(join(TEST_DIR, "signet.yml"));

    const { exitCode } = runSignet(`eval "npm test" --agent bot --token ${TOKEN_PATH}`);

    expect(exitCode).toBe(0);
    expect(readAudit().entries.length).toBe(1);
  });

  test("a token whose scope was edited after signing is denied", () => {
    setupAgent("bot", userKey);
    const token = JSON.parse(readFileSync(TOKEN_PATH, "utf-8"));
    token.scope = { shell: { allow: ["*"] } };
    writeFileSync(TOKEN_PATH, JSON.stringify(token));

    const { exitCode } = runSignet(`eval "rm -rf /" --agent bot --token ${TOKEN_PATH}`);

    const { entries } = readAudit();
    expect(exitCode).toBe(1);
    expect(entries.length).toBe(1);
    expect(entries[0].decision.reason).toBe("Invalid delegation token signature");
  });
});

describe("signet eval: context-bound tokens", () => {
  const BOUND = { context_hash: "a".repeat(64) };

  test("without a context hash the request is not evaluated", () => {
    setupAgent("bot", userKey, POLICY_YML, BOUND);

    const { stderr, exitCode } = runSignet(`eval "npm test" --agent bot --token ${TOKEN_PATH}`);

    expect(exitCode).toBe(2);
    expect(stderr).toContain("--context-hash");
    expect(readAudit().entries.length).toBe(0);
  });

  test("a matching context hash is allowed", () => {
    setupAgent("bot", userKey, POLICY_YML, BOUND);

    const { exitCode } = runSignet(
      `eval "npm test" --agent bot --token ${TOKEN_PATH} --context-hash ${BOUND.context_hash}`,
    );

    expect(exitCode).toBe(0);
  });

  test("a different context hash is denied and logged", () => {
    setupAgent("bot", userKey, POLICY_YML, BOUND);

    const { exitCode } = runSignet(
      `eval "npm test" --agent bot --token ${TOKEN_PATH} --context-hash ${"b".repeat(64)}`,
    );

    const { entries } = readAudit();
    expect(exitCode).toBe(1);
    expect(entries[0].decision.reason).toBe("Context hash mismatch");
  });
});

describe("signet eval: input validation", () => {
  test("a type that is only an Object.prototype key is rejected", () => {
    setupAgent("bot", userKey);

    const { stderr, exitCode } = runSignet(`eval "npm test" --type constructor --agent bot --token ${TOKEN_PATH}`);

    expect(exitCode).toBe(2);
    expect(stderr).toContain("Unknown type");
    expect(readAudit().entries.length).toBe(0);
  });

  test("a token whose expiry is not a date is rejected", () => {
    setupAgent("bot", userKey);
    const token = JSON.parse(readFileSync(TOKEN_PATH, "utf-8"));
    token.expires_at = "not-a-date";
    writeFileSync(TOKEN_PATH, JSON.stringify(token));

    const { stderr, exitCode } = runSignet(`eval "npm test" --agent bot --token ${TOKEN_PATH}`);

    expect(exitCode).toBe(2);
    expect(stderr).toContain("Malformed delegation token");
  });
});

describe("signet eval: concurrent callers", () => {
  test("parallel evaluations keep the hash chain valid", async () => {
    setupAgent("bot", userKey);
    const cmd = `npx tsx ${join(process.cwd(), "src/index.ts")} eval "npm test" --agent bot --token ${TOKEN_PATH}`;
    const env = { ...process.env, HOME: TEST_DIR, SIGNET_AGENT: "", SIGNET_TOKEN: "" };

    await Promise.all(
      Array.from({ length: 16 }, () => promisify(exec)(cmd, { cwd: TEST_DIR, env, timeout: 90000 })),
    );

    const { entries, chainValid } = readAudit();
    expect(entries.length).toBe(16);
    expect(chainValid).toBe(true);
  }, 120000);
});

describe("generic wrapper generation", () => {
  test("a pattern whose first word is a path writes no file outside the bin directory", () => {
    const binDir = join(TEST_DIR, "wrappers", "bin");
    const scope = parsePolicy(`version: 1\nscope:\n  shell:\n    deny:\n      - "../pwned *"\n      - "rm -rf *"\n`).scope;

    const wrapped = generateWrappers(scope, binDir);

    expect(wrapped).toEqual(["rm"]);
    expect(existsSync(join(TEST_DIR, "wrappers", "pwned"))).toBe(false);
  });
});

describe("audit log write", () => {
  test("log() throws when the row is not inserted", () => {
    const logger = new AuditLogger(AUDIT_DB);
    logger.close();
    const db = new Database(AUDIT_DB);
    db.exec("CREATE TRIGGER drop_rows BEFORE INSERT ON audit_log BEGIN SELECT RAISE(IGNORE); END;");
    db.close();
    const reopened = new AuditLogger(AUDIT_DB);
    const request = { agent_id: "a", action: "shell", target: "npm test", timestamp: "t", signature: "s" };
    const decision = { request_hash: "h", allowed: true, reason: "r", decided_by: "policy" as const, timestamp: "t", signature: "s" };

    const act = () => reopened.log(request, decision);

    expect(act).toThrow("not written");
    reopened.close();
  });
});

const WRAPPER_POLICY_YML = `version: 1
scope:
  shell:
    allow:
      - "fakecmd *"
    deny:
      - "fakecmd -rf *"
`;

describe("generic wrapper (end to end)", () => {
  const binDir = join(SIGNET_HOME, "bin");
  const realDir = join(TEST_DIR, "real");
  const shimDir = join(TEST_DIR, "shim");
  const nodeBin = dirname(execSync("command -v npx", { encoding: "utf-8" }).trim());

  function setupWrapper(withSignet: boolean): string {
    setupAgent("bot", userKey, WRAPPER_POLICY_YML);
    generateWrappers(parsePolicy(WRAPPER_POLICY_YML).scope, binDir);
    mkdirSync(realDir, { recursive: true });
    writeFileSync(join(realDir, "fakecmd"), `#!/bin/sh\necho "RAN:$*"\n`, { mode: 0o755 });
    mkdirSync(shimDir, { recursive: true });
    if (withSignet) {
      writeFileSync(
        join(shimDir, "signet"),
        `#!/bin/sh\nexec npx tsx ${join(process.cwd(), "src/index.ts")} "$@"\n`,
        { mode: 0o755 },
      );
    }
    return `${binDir}:${shimDir}:${realDir}:${nodeBin}:/usr/bin:/bin`;
  }

  function runWrapped(path: string, args: string[], env: Record<string, string> = {}) {
    const r = spawnSync("fakecmd", args, {
      cwd: TEST_DIR,
      env: { ...process.env, HOME: TEST_DIR, PATH: path, SIGNET_AGENT: "bot", SIGNET_TOKEN: TOKEN_PATH, ...env },
      encoding: "utf-8",
      timeout: 20000,
    });
    return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", exitCode: r.status };
  }

  test("an allowed command runs and is logged", () => {
    const path = setupWrapper(true);

    const { stdout, exitCode } = runWrapped(path, ["hello"]);

    const { entries } = readAudit();
    expect(exitCode).toBe(0);
    expect(stdout).toContain("RAN:hello");
    expect(entries.length).toBe(1);
    expect(entries[0].request.target).toBe("fakecmd hello");
  });

  test("a denied command does not run and the denial is logged", () => {
    const path = setupWrapper(true);

    const { stdout, exitCode } = runWrapped(path, ["-rf", "x"]);

    const { entries } = readAudit();
    expect(exitCode).toBe(1);
    expect(stdout).not.toContain("RAN:");
    expect(entries.length).toBe(1);
    expect(entries[0].decision.allowed).toBe(false);
  });

  test("an empty argument cannot push a command past a deny rule", () => {
    const path = setupWrapper(true);

    const { stdout, exitCode } = runWrapped(path, ["", "-rf", "x"]);

    expect(exitCode).toBe(1);
    expect(stdout).not.toContain("RAN:");
    expect(readAudit().entries[0].request.target).toBe("fakecmd -rf x");
  });

  test("the command is blocked when signet is not on PATH", () => {
    const path = setupWrapper(false);

    const { stdout, stderr, exitCode } = runWrapped(path, ["hello"]);

    expect(exitCode).toBe(1);
    expect(stdout).not.toContain("RAN:");
    expect(stderr).toContain("signet not found");
  });

  test("the command is blocked when SIGNET_AGENT / SIGNET_TOKEN are unset", () => {
    const path = setupWrapper(true);

    const { stdout, exitCode } = runWrapped(path, ["hello"], { SIGNET_AGENT: "", SIGNET_TOKEN: "" });

    expect(exitCode).toBe(1);
    expect(stdout).not.toContain("RAN:");
    expect(readAudit().entries.length).toBe(0);
  });

  function runWrappedBounded(path: string, args: string[]) {
    const r = spawnSync("fakecmd", args, {
      cwd: TEST_DIR,
      env: { ...process.env, HOME: TEST_DIR, PATH: path, SIGNET_AGENT: "bot", SIGNET_TOKEN: TOKEN_PATH },
      encoding: "utf-8",
      timeout: 8000,
    });
    return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", exitCode: r.status };
  }

  test("the wrapper does not run itself when its directory is the last PATH entry", () => {
    setupWrapper(true);
    const path = `${shimDir}:${nodeBin}:/usr/bin:/bin:${binDir}`;

    const { stderr, exitCode } = runWrappedBounded(path, ["hello"]);

    expect(exitCode).toBe(127);
    expect(stderr).toContain("original 'fakecmd' not found");
    expect(readAudit().entries.length).toBe(0);
  }, 30000);

  test("the real command runs once when the wrapper directory is on PATH with a trailing slash", () => {
    setupWrapper(true);
    const path = `${binDir}/:${shimDir}:${realDir}:${nodeBin}:/usr/bin:/bin`;

    const { stdout, exitCode } = runWrappedBounded(path, ["hello"]);

    expect(exitCode).toBe(0);
    expect(stdout).toContain("RAN:hello");
    expect(readAudit().entries.length).toBe(1);
  }, 30000);
});

describe("generic wrapper", () => {
  test("gates on signet eval, not the dry-run check", () => {
    const binDir = join(TEST_DIR, "bin");
    generateWrappers(parsePolicy(POLICY_YML).scope, binDir);

    const script = readFileSync(join(binDir, "rm"), "utf-8");

    expect(script).toContain('signet eval "$FULL_CMD"');
    expect(script).not.toContain("signet check");
  });
});
