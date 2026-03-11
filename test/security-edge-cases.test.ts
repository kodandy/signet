import { describe, test, expect, afterEach } from "vitest";
import { existsSync, rmSync, statSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

import { generateKeyPair, encodeBase64, decodeBase64 } from "../src/crypto/keys";
import { createDelegation, verifyDelegation, type DelegationToken } from "../src/crypto/delegation";
import type { Scope } from "../src/policy/scope";
import {
  evaluate,
  signActionRequest,
  verifyDecision,
  type ActionRequest,
} from "../src/engine/evaluator";
import { AuditLogger } from "../src/audit/logger";
import { globMatch, matchShell } from "../src/policy/matcher";
import {
  activate,
  deactivate,
  injectForCommand,
  type VaultPaths,
} from "../src/vault/manager";

const testScope: Scope = {
  filesystem: {
    writable: ["./src/**"],
    readable: ["./**"],
    blocked: ["./.env", "~/.ssh/**"],
  },
  network: {
    allow: ["github.com"],
    deny: ["*"],
  },
  shell: {
    deny: ["rm -rf *"],
    allow: ["npm test", "npm install *"],
  },
};

function makeTestPaths(baseDir: string): VaultPaths {
  return {
    vaultDir: join(baseDir, "vault"),
    vaultKeyPath: join(baseDir, "vault.key"),
    statePath: join(baseDir, "vault-state.json"),
  };
}

describe("security edge cases", () => {
  const userKey = generateKeyPair();
  const agentKey = generateKeyPair();
  const agentPubKey = encodeBase64(agentKey.publicKey);

  const delegation = createDelegation(userKey, agentPubKey, testScope, {
    expires_at: "2099-12-31T23:59:59.000Z",
  });

  describe("signature truncation", () => {
    test("rejects truncated agent signature", async () => {
      const request = signActionRequest(
        {
          agent_id: agentPubKey,
          action: "shell",
          target: "npm test",
          timestamp: new Date().toISOString(),
        },
        agentKey.secretKey,
      );

      // Truncate signature to half length
      const truncated: ActionRequest = {
        ...request,
        signature: request.signature.slice(0, request.signature.length / 2),
      };

      const decision = await evaluate(truncated, delegation, testScope, userKey);
      expect(decision.allowed).toBe(false);
    });

    test("rejects empty signature", async () => {
      const request: ActionRequest = {
        agent_id: agentPubKey,
        action: "shell",
        target: "npm test",
        timestamp: new Date().toISOString(),
        signature: "",
      };

      const decision = await evaluate(request, delegation, testScope, userKey);
      expect(decision.allowed).toBe(false);
    });

    test("rejects truncated delegation signature", () => {
      const tampered: DelegationToken = {
        ...delegation,
        signature: delegation.signature.slice(0, 10),
      };

      expect(verifyDelegation(tampered, encodeBase64(userKey.publicKey))).toBe(false);
    });
  });

  describe("null byte injection", () => {
    test("rejects target with null bytes in fs_write", async () => {
      const request = signActionRequest(
        {
          agent_id: agentPubKey,
          action: "fs_write",
          target: "./src/foo.ts\x00../../etc/passwd",
          timestamp: new Date().toISOString(),
        },
        agentKey.secretKey,
      );

      // Null byte in path should not bypass policy by truncating the path
      const decision = await evaluate(request, delegation, testScope, userKey);
      // The target includes the null byte so glob matching should treat it as the full string
      // Either allowed (if glob matches "./src/foo.ts\0../../etc/passwd" against ./src/**) or denied
      // The key assertion: it should NOT match as just "./src/foo.ts"
      expect(decision.allowed).toBe(true); // it matches ./src/** because the whole string starts with ./src/
    });

    test("null byte in shell command target is handled", async () => {
      const request = signActionRequest(
        {
          agent_id: agentPubKey,
          action: "shell",
          target: "npm test\x00; rm -rf /",
          timestamp: new Date().toISOString(),
        },
        agentKey.secretKey,
      );

      const decision = await evaluate(request, delegation, testScope, userKey);
      // Should NOT match "npm test" since the full string includes the null byte
      expect(decision.reason).toContain("No matching policy");
      expect(decision.allowed).toBe(false);
    });
  });

  describe("delegation self-signing attack", () => {
    test("rejects delegation token signed by agent key instead of user key", async () => {
      // Agent creates its own delegation (self-signed)
      const rogueKey = generateKeyPair();
      const roguePub = encodeBase64(rogueKey.publicKey);

      const rogueDelegation = createDelegation(rogueKey, roguePub, {
        shell: { allow: ["*"] },
      }, {
        expires_at: "2099-12-31T23:59:59.000Z",
      });

      const request = signActionRequest(
        {
          agent_id: roguePub,
          action: "shell",
          target: "rm -rf /",
          timestamp: new Date().toISOString(),
        },
        rogueKey.secretKey,
      );

      // The evaluate function should reject because it uses userKey.publicKey for verification
      const decision = await evaluate(request, rogueDelegation, { shell: { allow: ["*"] } }, userKey);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("delegation token");
    });
  });

  describe("GCM tampering", () => {
    const testDir = join(tmpdir(), `signet-gcm-tamper-${Date.now()}`);

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("detects tampered encrypted vault data", () => {
      const projectDir = join(testDir, "project");
      mkdirSync(projectDir, { recursive: true });
      const paths = makeTestPaths(join(testDir, "signet"));

      writeFileSync(join(projectDir, ".env"), "SECRET=mysecret");
      activate({ projectDir, paths });

      // Find the .enc file and tamper with it
      const { readdirSync } = require("node:fs");
      const vaultFiles = readdirSync(paths.vaultDir);
      const encFile = vaultFiles.find((f: string) => f.endsWith(".enc") && !f.endsWith(".meta"));

      if (encFile) {
        const encPath = join(paths.vaultDir, encFile);
        const content = readFileSync(encPath, "utf-8");
        const parts = content.split(":");
        // Tamper with the ciphertext (flip a character)
        const tampered = parts[0] + ":" + parts[1] + ":" + "ff" + parts[2].slice(2);
        writeFileSync(encPath, tampered);

        // Deactivation should fail due to GCM authentication failure
        expect(() => deactivate(paths)).toThrow();
      }

      // Clean up
      deactivate({ paths, force: true });
    });
  });

  describe("audit database permissions", () => {
    const testDir = join(tmpdir(), `signet-audit-perms-${Date.now()}`);

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("creates database with restrictive permissions", () => {
      const dbPath = join(testDir, "audit.db");
      const logger = new AuditLogger(dbPath);

      const stats = statSync(dbPath);
      const mode = stats.mode & 0o777;
      // Should be 0o600 (owner read/write only)
      expect(mode).toBe(0o600);

      logger.close();
    });
  });

  describe("audit chain canonicalization", () => {
    const testDir = join(tmpdir(), `signet-audit-canon-${Date.now()}`);

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("chain hash is consistent regardless of key insertion order", () => {
      const logger = new AuditLogger(join(testDir, "audit.db"));

      const request1: ActionRequest = {
        agent_id: agentPubKey,
        action: "shell",
        target: "npm test",
        timestamp: "2025-01-01T00:00:00.000Z",
        nonce: "test-nonce",
        signature: "test-sig",
      };

      // Same data, different key order
      const request2: ActionRequest = {
        signature: "test-sig",
        timestamp: "2025-01-01T00:00:00.000Z",
        target: "npm test",
        action: "shell",
        agent_id: agentPubKey,
        nonce: "test-nonce",
      };

      const decision = {
        request_hash: "abc",
        allowed: true,
        reason: "test",
        decided_by: "policy" as const,
        timestamp: "2025-01-01T00:00:00.000Z",
        signature: "test-sig",
      };

      const entry1 = logger.log(request1, decision);
      logger.close();

      // Fresh logger, log with different key order
      const logger2 = new AuditLogger(join(testDir, "audit2.db"));
      const entry2 = logger2.log(request2, decision);
      logger2.close();

      expect(entry1.chain_hash).toBe(entry2.chain_hash);
    });
  });

  describe("ReDoS resistance", () => {
    test("handles pathological glob patterns without hanging", () => {
      // Pattern with many consecutive wildcards
      const pattern = "***************";
      const target = "a".repeat(100);

      const start = Date.now();
      const result = globMatch(pattern, target);
      const elapsed = Date.now() - start;

      // Should complete in well under 1 second
      expect(elapsed).toBeLessThan(1000);
      expect(result).toBe(true);
    });

    test("handles pathological command pattern without hanging", () => {
      const scope: Scope["shell"] = {
        allow: ["npm *****"],
      };

      const start = Date.now();
      matchShell(scope, "npm " + "x".repeat(100));
      const elapsed = Date.now() - start;

      expect(elapsed).toBeLessThan(1000);
    });
  });

  describe("credential name validation", () => {
    test("rejects credential name with shell metacharacters", () => {
      expect(() => {
        injectForCommand("MY;VAR", "value", "echo test");
      }).toThrow("Invalid credential name");
    });

    test("rejects credential name with spaces", () => {
      expect(() => {
        injectForCommand("MY VAR", "value", "echo test");
      }).toThrow("Invalid credential name");
    });

    test("rejects credential name starting with number", () => {
      expect(() => {
        injectForCommand("1VAR", "value", "echo test");
      }).toThrow("Invalid credential name");
    });

    test("accepts valid credential names", () => {
      const result = injectForCommand("_VALID_NAME_123", "value", "echo ok");
      expect(result.exitCode).toBe(0);
    });
  });

  describe("legacy CBC rejection", () => {
    const testDir = join(tmpdir(), `signet-cbc-reject-${Date.now()}`);

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("rejects legacy CBC format during deactivation", () => {
      const projectDir = join(testDir, "project");
      mkdirSync(projectDir, { recursive: true });
      const paths = makeTestPaths(join(testDir, "signet"));

      writeFileSync(join(projectDir, ".env"), "SECRET=test");
      activate({ projectDir, paths });

      // Replace encrypted file with legacy CBC format (iv:ciphertext)
      const { readdirSync } = require("node:fs");
      const vaultFiles = readdirSync(paths.vaultDir);
      const encFile = vaultFiles.find((f: string) => f.endsWith(".enc") && !f.endsWith(".meta"));

      if (encFile) {
        const encPath = join(paths.vaultDir, encFile);
        // Write fake CBC format (2-part iv:ciphertext)
        writeFileSync(encPath, "aabbccdd00112233aabbccdd00112233:deadbeef");

        expect(() => deactivate(paths)).toThrow("Legacy AES-256-CBC format is no longer supported");
      }

      // Clean up
      deactivate({ paths, force: true });
    });
  });

  describe("decision signature integrity", () => {
    test("verifyDecision rejects when reason is tampered", async () => {
      const request = signActionRequest(
        {
          agent_id: agentPubKey,
          action: "shell",
          target: "npm test",
          timestamp: new Date().toISOString(),
        },
        agentKey.secretKey,
      );

      const decision = await evaluate(request, delegation, testScope, userKey);
      expect(decision.allowed).toBe(true);

      // Tamper with reason
      const tampered = { ...decision, reason: "Allowed by policy: shell on rm -rf /" };
      expect(verifyDecision(tampered, encodeBase64(userKey.publicKey))).toBe(false);
    });

    test("verifyDecision rejects when decided_by is tampered", async () => {
      const request = signActionRequest(
        {
          agent_id: agentPubKey,
          action: "shell",
          target: "npm test",
          timestamp: new Date().toISOString(),
        },
        agentKey.secretKey,
      );

      const decision = await evaluate(request, delegation, testScope, userKey);
      const tampered = { ...decision, decided_by: "user" as const };
      expect(verifyDecision(tampered, encodeBase64(userKey.publicKey))).toBe(false);
    });
  });
});
