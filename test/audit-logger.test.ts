import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateKeyPair, encodeBase64 } from "../src/crypto/keys";
import { signActionRequest } from "../src/engine/evaluator";
import type { ActionRequest, ActionDecision } from "../src/engine/evaluator";
import { AuditLogger } from "../src/audit/logger";

function makeTestRequest(agentKey: ReturnType<typeof generateKeyPair>): ActionRequest {
  return signActionRequest(
    {
      agent_id: encodeBase64(agentKey.publicKey),
      action: "shell",
      target: "npm test",
      timestamp: new Date().toISOString(),
    },
    agentKey.secretKey,
  );
}

function makeTestDecision(requestHash: string = "abc123"): ActionDecision {
  return {
    request_hash: requestHash,
    allowed: true,
    reason: "Allowed by policy",
    decided_by: "policy",
    timestamp: new Date().toISOString(),
    signature: "test-signature",
  };
}

describe("audit/logger", () => {
  const testDir = join(tmpdir(), `signet-audit-test-${Date.now()}`);
  const dbPath = join(testDir, "test-audit.db");
  let logger: AuditLogger;

  beforeEach(() => {
    logger = new AuditLogger(dbPath);
  });

  afterEach(() => {
    logger.close();
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  describe("log", () => {
    test("logs an entry and returns it", () => {
      const agentKey = generateKeyPair();
      const request = makeTestRequest(agentKey);
      const decision = makeTestDecision();

      const entry = logger.log(request, decision);

      expect(entry.id).toBe(1);
      expect(entry.request).toEqual(request);
      expect(entry.decision).toEqual(decision);
      expect(entry.chain_hash).toMatch(/^[a-f0-9]{64}$/);
      expect(entry.previous_hash).toBe("genesis");
    });

    test("chains hashes sequentially", () => {
      const agentKey = generateKeyPair();

      const entry1 = logger.log(makeTestRequest(agentKey), makeTestDecision("h1"));
      const entry2 = logger.log(makeTestRequest(agentKey), makeTestDecision("h2"));
      const entry3 = logger.log(makeTestRequest(agentKey), makeTestDecision("h3"));

      expect(entry1.previous_hash).toBe("genesis");
      expect(entry2.previous_hash).toBe(entry1.chain_hash);
      expect(entry3.previous_hash).toBe(entry2.chain_hash);

      // 全て異なるハッシュ
      const hashes = [entry1.chain_hash, entry2.chain_hash, entry3.chain_hash];
      expect(new Set(hashes).size).toBe(3);
    });
  });

  describe("verify", () => {
    test("verifies empty log", () => {
      const result = logger.verify();

      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.entries_checked).toBe(0);
    });

    test("verifies valid chain", () => {
      const agentKey = generateKeyPair();
      logger.log(makeTestRequest(agentKey), makeTestDecision("h1"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h2"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h3"));

      const result = logger.verify();

      expect(result.valid).toBe(true);
      expect(result.entries_checked).toBe(3);
    });

    test("detects tampered data", () => {
      const agentKey = generateKeyPair();
      logger.log(makeTestRequest(agentKey), makeTestDecision("h1"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h2"));

      // 直接DBを改竄
      const db = (logger as any).db;
      db.prepare("UPDATE audit_log SET decision_json = ? WHERE id = 1").run(
        JSON.stringify({ ...makeTestDecision("h1"), allowed: false }),
      );

      const result = logger.verify();

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain("chain_hash mismatch");
    });

    test("detects deleted entry (chain break)", () => {
      const agentKey = generateKeyPair();
      logger.log(makeTestRequest(agentKey), makeTestDecision("h1"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h2"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h3"));

      // 中間エントリを削除
      const db = (logger as any).db;
      db.prepare("DELETE FROM audit_log WHERE id = 2").run();

      const result = logger.verify();

      expect(result.valid).toBe(false);
      expect(result.errors.some((e: string) => e.includes("previous_hash mismatch"))).toBe(true);
    });
  });

  describe("exportLog", () => {
    test("exports as JSON", () => {
      const agentKey = generateKeyPair();
      logger.log(makeTestRequest(agentKey), makeTestDecision("h1"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h2"));

      const json = logger.exportLog("json");
      const parsed = JSON.parse(json);

      expect(parsed).toHaveLength(2);
      expect(parsed[0].id).toBe(1);
      expect(parsed[0].request.action).toBe("shell");
      expect(parsed[1].id).toBe(2);
    });

    test("exports as CSV", () => {
      const agentKey = generateKeyPair();
      logger.log(makeTestRequest(agentKey), makeTestDecision("h1"));

      const csv = logger.exportLog("csv");
      const lines = csv.split("\n");

      expect(lines[0]).toBe("id,timestamp,action,target,allowed,reason,decided_by,chain_hash");
      expect(lines[1]).toContain("shell");
      expect(lines[1]).toContain("npm test");
    });
  });

  describe("getEntries", () => {
    test("returns entries in reverse order", () => {
      const agentKey = generateKeyPair();
      logger.log(makeTestRequest(agentKey), makeTestDecision("h1"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h2"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h3"));

      const entries = logger.getEntries();

      expect(entries).toHaveLength(3);
      expect(entries[0].id).toBe(3);
      expect(entries[2].id).toBe(1);
    });

    test("respects limit parameter", () => {
      const agentKey = generateKeyPair();
      logger.log(makeTestRequest(agentKey), makeTestDecision("h1"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h2"));
      logger.log(makeTestRequest(agentKey), makeTestDecision("h3"));

      const entries = logger.getEntries(2);

      expect(entries).toHaveLength(2);
      expect(entries[0].id).toBe(3);
    });
  });
});
