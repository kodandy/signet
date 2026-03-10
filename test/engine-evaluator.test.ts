import { describe, test, expect, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateKeyPair, encodeBase64, sign } from "../src/crypto/keys";
import { createDelegation } from "../src/crypto/delegation";
import type { Scope } from "../src/policy/scope";
import {
  evaluate,
  signActionRequest,
  verifyDecision,
  type ActionRequest,
} from "../src/engine/evaluator";
import { AuditLogger } from "../src/audit/logger";

// テスト用ヘルパー
function makeSignedRequest(
  agentSecretKey: Uint8Array,
  agentPubKey: string,
  action: string,
  target: string,
  purpose?: string,
): ActionRequest {
  return signActionRequest(
    {
      agent_id: agentPubKey,
      action,
      target,
      timestamp: new Date().toISOString(),
      ...(purpose !== undefined && { purpose }),
    },
    agentSecretKey,
  );
}

const testScope: Scope = {
  filesystem: {
    writable: ["./src/**", "./test/**"],
    readable: ["./**"],
    blocked: ["./.env", "~/.ssh/**"],
  },
  network: {
    allow: ["github.com", "registry.npmjs.org"],
    deny: ["*"],
  },
  shell: {
    deny: ["rm -rf *", "sudo *"],
    ask: ["git push *"],
    allow: ["npm test", "npm install *"],
  },
  credentials: {
    github_token: {
      allowed_actions: ["git push", "gh pr create"],
      require_approval: false,
    },
    aws: {
      allowed_actions: ["aws s3 ls"],
      require_approval: true,
    },
  },
};

describe("engine/evaluator", () => {
  // 共通セットアップ
  const userKey = generateKeyPair();
  const agentKey = generateKeyPair();
  const agentPubKey = encodeBase64(agentKey.publicKey);

  const delegation = createDelegation(userKey, agentPubKey, testScope, {
    expires_at: "2099-12-31T23:59:59.000Z",
  });

  describe("署名検証", () => {
    test("rejects invalid agent signature", async () => {
      const request: ActionRequest = {
        agent_id: agentPubKey,
        action: "shell",
        target: "npm test",
        timestamp: new Date().toISOString(),
        signature: encodeBase64(new Uint8Array(64)), // 無効な署名
      };

      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("Invalid agent signature");
      expect(decision.decided_by).toBe("policy");
    });

    test("rejects request from unauthorized agent", async () => {
      const rogueAgent = generateKeyPair();
      const roguePubKey = encodeBase64(rogueAgent.publicKey);
      const request = makeSignedRequest(rogueAgent.secretKey, roguePubKey, "shell", "npm test");

      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("Agent not authorized");
    });
  });

  describe("DelegationToken検証", () => {
    test("rejects expired delegation token", async () => {
      const expiredDelegation = createDelegation(userKey, agentPubKey, testScope, {
        expires_at: "2000-01-01T00:00:00.000Z",
      });
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");

      const decision = await evaluate(request, expiredDelegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("expired");
    });
  });

  describe("ファイルシステム判定", () => {
    test("allows write to src/", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "fs_write", "./src/foo.ts");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(true);
      expect(decision.decided_by).toBe("policy");
    });

    test("denies write to .env", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "fs_write", "./.env");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
    });

    test("allows read from project root", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "fs_read", "./package.json");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(true);
    });

    test("denies read from ~/.ssh", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "fs_read", "~/.ssh/id_rsa");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
    });
  });

  describe("ネットワーク判定", () => {
    test("allows whitelisted domain", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "net_connect", "github.com");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(true);
    });

    test("denies non-whitelisted domain", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "net_connect", "evil.com");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
    });
  });

  describe("シェルコマンド判定", () => {
    test("allows npm test", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(true);
    });

    test("denies rm -rf /", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "rm -rf /");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
    });

    test("asks for git push and approves via callback", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "git push origin main");
      const decision = await evaluate(request, delegation, testScope, userKey, {
        onAsk: async () => true,
      });

      expect(decision.allowed).toBe(true);
      expect(decision.decided_by).toBe("user");
    });

    test("asks for git push and rejects via callback", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "git push origin main");
      const decision = await evaluate(request, delegation, testScope, userKey, {
        onAsk: async () => false,
      });

      expect(decision.allowed).toBe(false);
      expect(decision.decided_by).toBe("user");
    });

    test("denies ask when no callback provided", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "git push origin main");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("Requires user approval");
    });

    test("propagates error when onAsk callback throws", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "git push origin main");
      await expect(
        evaluate(request, delegation, testScope, userKey, {
          onAsk: async () => {
            throw new Error("callback error");
          },
        }),
      ).rejects.toThrow("callback error");
    });
  });

  describe("クレデンシャル判定", () => {
    test("allows github_token for git push", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "use_credential", "github_token", "git push");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(true);
    });

    test("denies unknown credential", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "use_credential", "unknown_key", "action");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
    });

    test("asks for aws credential approval", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "use_credential", "aws", "aws s3 ls");
      const decision = await evaluate(request, delegation, testScope, userKey, {
        onAsk: async () => true,
      });

      expect(decision.allowed).toBe(true);
      expect(decision.decided_by).toBe("user");
    });
  });

  describe("ActionDecision署名", () => {
    test("all decisions are signed by user key", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.signature).toBeTruthy();
      expect(verifyDecision(decision, encodeBase64(userKey.publicKey))).toBe(true);
    });

    test("decision signature rejects tampering", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, delegation, testScope, userKey);

      const tampered = { ...decision, allowed: false };
      expect(verifyDecision(tampered, encodeBase64(userKey.publicKey))).toBe(false);
    });

    test("decision includes request_hash", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.request_hash).toMatch(/^[a-f0-9]{64}$/);
    });

    test("signActionRequest produces consistent signature for same input", () => {
      const fixedTimestamp = "2025-01-01T00:00:00.000Z";
      const req1 = signActionRequest(
        { agent_id: agentPubKey, action: "shell", target: "npm test", timestamp: fixedTimestamp },
        agentKey.secretKey,
      );
      const req2 = signActionRequest(
        { agent_id: agentPubKey, action: "shell", target: "npm test", timestamp: fixedTimestamp },
        agentKey.secretKey,
      );

      expect(req1.signature).toBe(req2.signature);
    });

    test("verifyDecision returns false for invalid base64 pubkey", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(verifyDecision(decision, "!!!invalid-base64!!!")).toBe(false);
    });
  });

  describe("未知のアクション", () => {
    test("denies unknown action type", async () => {
      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "unknown_action", "something");
      const decision = await evaluate(request, delegation, testScope, userKey);

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("No matching policy");
    });
  });

  describe("max_uses enforcement", () => {
    const testDir = join(tmpdir(), `signet-engine-maxuses-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    let logger: AuditLogger;

    afterEach(() => {
      logger?.close();
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("enforces delegation token max_uses", async () => {
      logger = new AuditLogger(join(testDir, "test.db"));
      const limitedDelegation = createDelegation(userKey, agentPubKey, testScope, {
        expires_at: "2099-12-31T23:59:59.000Z",
        max_uses: 2,
      });

      // 1st use - allowed
      const req1 = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const d1 = await evaluate(req1, limitedDelegation, testScope, userKey, { auditLogger: logger });
      expect(d1.allowed).toBe(true);

      // 2nd use - allowed
      const req2 = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const d2 = await evaluate(req2, limitedDelegation, testScope, userKey, { auditLogger: logger });
      expect(d2.allowed).toBe(true);

      // 3rd use - denied (max_uses exceeded)
      const req3 = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const d3 = await evaluate(req3, limitedDelegation, testScope, userKey, { auditLogger: logger });
      expect(d3.allowed).toBe(false);
      expect(d3.reason).toContain("max_uses exceeded");
    });

    test("enforces credential max_uses", async () => {
      logger = new AuditLogger(join(testDir, "test2.db"));
      const scopeWithCredMaxUses: Scope = {
        ...testScope,
        credentials: {
          limited_token: {
            allowed_actions: ["*"],
            max_uses: 1,
            require_approval: false,
          },
        },
      };

      const credDelegation = createDelegation(userKey, agentPubKey, scopeWithCredMaxUses, {
        expires_at: "2099-12-31T23:59:59.000Z",
      });

      // 1st use - allowed
      const req1 = makeSignedRequest(agentKey.secretKey, agentPubKey, "use_credential", "limited_token", "some action");
      const d1 = await evaluate(req1, credDelegation, scopeWithCredMaxUses, userKey, { auditLogger: logger });
      expect(d1.allowed).toBe(true);

      // 2nd use - denied
      const req2 = makeSignedRequest(agentKey.secretKey, agentPubKey, "use_credential", "limited_token", "some action");
      const d2 = await evaluate(req2, credDelegation, scopeWithCredMaxUses, userKey, { auditLogger: logger });
      expect(d2.allowed).toBe(false);
      expect(d2.reason).toContain("Credential max_uses exceeded");
    });

    test("works without auditLogger (backwards compatible)", async () => {
      // No auditLogger → max_uses not enforced, still works
      const limitedDelegation = createDelegation(userKey, agentPubKey, testScope, {
        expires_at: "2099-12-31T23:59:59.000Z",
        max_uses: 1,
      });

      const req1 = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const d1 = await evaluate(req1, limitedDelegation, testScope, userKey);
      expect(d1.allowed).toBe(true);

      // Without auditLogger, max_uses is not enforced
      const req2 = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const d2 = await evaluate(req2, limitedDelegation, testScope, userKey);
      expect(d2.allowed).toBe(true);
    });
  });

  describe("token revocation", () => {
    const testDir = join(tmpdir(), `signet-engine-revoke-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    let logger: AuditLogger;

    afterEach(() => {
      logger?.close();
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("denies request with revoked delegation token", async () => {
      logger = new AuditLogger(join(testDir, "test.db"));

      const tokenHash = createHash("sha256")
        .update(delegation.signature)
        .digest("hex");
      logger.revokeToken(tokenHash, "test revocation");

      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, delegation, testScope, userKey, { auditLogger: logger });

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("revoked");
    });

    test("allows request with non-revoked token", async () => {
      logger = new AuditLogger(join(testDir, "test2.db"));

      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, delegation, testScope, userKey, { auditLogger: logger });

      expect(decision.allowed).toBe(true);
    });
  });

  describe("context_hash validation", () => {
    const testDir = join(tmpdir(), `signet-engine-ctx-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    let logger: AuditLogger;

    afterEach(() => {
      logger?.close();
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("denies when context_hash does not match", async () => {
      logger = new AuditLogger(join(testDir, "test.db"));

      const contextDelegation = createDelegation(userKey, agentPubKey, testScope, {
        expires_at: "2099-12-31T23:59:59.000Z",
        context_hash: "expected_hash_value",
      });

      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, contextDelegation, testScope, userKey, {
        auditLogger: logger,
        context_hash: "different_hash_value",
      });

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("Context hash mismatch");
    });

    test("allows when context_hash matches", async () => {
      logger = new AuditLogger(join(testDir, "test2.db"));

      const contextDelegation = createDelegation(userKey, agentPubKey, testScope, {
        expires_at: "2099-12-31T23:59:59.000Z",
        context_hash: "matching_hash",
      });

      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, contextDelegation, testScope, userKey, {
        auditLogger: logger,
        context_hash: "matching_hash",
      });

      expect(decision.allowed).toBe(true);
    });

    test("skips context_hash check when not provided in options", async () => {
      logger = new AuditLogger(join(testDir, "test3.db"));

      const contextDelegation = createDelegation(userKey, agentPubKey, testScope, {
        expires_at: "2099-12-31T23:59:59.000Z",
        context_hash: "some_hash",
      });

      const request = makeSignedRequest(agentKey.secretKey, agentPubKey, "shell", "npm test");
      const decision = await evaluate(request, contextDelegation, testScope, userKey, {
        auditLogger: logger,
      });

      // No context_hash in opts → skip check → allowed
      expect(decision.allowed).toBe(true);
    });
  });
});
