import { describe, test, expect } from "vitest";
import { generateKeyPair, encodeBase64 } from "../src/crypto/keys";
import {
  createDelegation,
  verifyDelegation,
  type Scope,
  type DelegationToken,
} from "../src/crypto/delegation";

const testScope: Scope = {
  filesystem: {
    writable: ["./src/**"],
    readable: ["./**"],
    blocked: ["./.env"],
  },
  shell: {
    deny: ["rm -rf *"],
  },
};

describe("crypto/delegation", () => {
  describe("createDelegation", () => {
    test("creates a valid delegation token with required fields", () => {
      // Arrange
      const userKey = generateKeyPair();
      const agentKey = generateKeyPair();
      const agentPubKey = encodeBase64(agentKey.publicKey);

      // Act
      const token = createDelegation(userKey, agentPubKey, testScope);

      // Assert
      expect(token.version).toBe(1);
      expect(token.issuer).toBe(encodeBase64(userKey.publicKey));
      expect(token.subject).toBe(agentPubKey);
      expect(token.scope).toEqual(testScope);
      expect(token.issued_at).toBeTruthy();
      expect(token.expires_at).toBeTruthy();
      expect(token.signature).toBeTruthy();
    });

    test("sets default expiry to 4 hours from now", () => {
      const userKey = generateKeyPair();
      const agentKey = generateKeyPair();
      const agentPubKey = encodeBase64(agentKey.publicKey);

      const before = Date.now();
      const token = createDelegation(userKey, agentPubKey, testScope);
      const after = Date.now();

      const issuedAt = new Date(token.issued_at).getTime();
      const expiresAt = new Date(token.expires_at).getTime();
      const fourHours = 4 * 60 * 60 * 1000;

      expect(issuedAt).toBeGreaterThanOrEqual(before);
      expect(issuedAt).toBeLessThanOrEqual(after);
      expect(expiresAt - issuedAt).toBe(fourHours);
    });

    test("respects custom expires_at", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);
      const customExpiry = "2099-12-31T23:59:59.000Z";

      const token = createDelegation(userKey, agentPubKey, testScope, {
        expires_at: customExpiry,
      });

      expect(token.expires_at).toBe(customExpiry);
    });

    test("includes optional max_uses", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope, {
        max_uses: 5,
      });

      expect(token.max_uses).toBe(5);
    });

    test("includes optional context_hash", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);
      const hash = "abc123def456";

      const token = createDelegation(userKey, agentPubKey, testScope, {
        context_hash: hash,
      });

      expect(token.context_hash).toBe(hash);
    });

    test("omits optional fields when not provided", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope);

      expect(token).not.toHaveProperty("max_uses");
      expect(token).not.toHaveProperty("context_hash");
    });
  });

  describe("verifyDelegation", () => {
    test("verifies a valid token", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope);
      const result = verifyDelegation(token, encodeBase64(userKey.publicKey));

      expect(result).toBe(true);
    });

    test("rejects token with wrong user public key", () => {
      const userKey = generateKeyPair();
      const otherUser = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope);
      const result = verifyDelegation(token, encodeBase64(otherUser.publicKey));

      expect(result).toBe(false);
    });

    test("rejects token with tampered scope", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);
      const userPubKey = encodeBase64(userKey.publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope);

      // 改竄: scopeを変更
      const tampered: DelegationToken = {
        ...token,
        scope: { shell: { allow: ["rm -rf /"] } },
      };

      expect(verifyDelegation(tampered, userPubKey)).toBe(false);
    });

    test("rejects token with tampered subject", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);
      const userPubKey = encodeBase64(userKey.publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope);

      // 改竄: subjectを別エージェントに差し替え
      const rogue = generateKeyPair();
      const tampered: DelegationToken = {
        ...token,
        subject: encodeBase64(rogue.publicKey),
      };

      expect(verifyDelegation(tampered, userPubKey)).toBe(false);
    });

    test("rejects token with tampered expires_at", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);
      const userPubKey = encodeBase64(userKey.publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope);

      // 改竄: 有効期限を延長
      const tampered: DelegationToken = {
        ...token,
        expires_at: "2099-12-31T23:59:59.000Z",
      };

      expect(verifyDelegation(tampered, userPubKey)).toBe(false);
    });

    test("rejects token with tampered signature", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);
      const userPubKey = encodeBase64(userKey.publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope);

      // 改竄: 署名のバイトをビットフリップで確実に破壊
      const sigBytes = new Uint8Array(
        Buffer.from(token.signature, "base64"),
      );
      sigBytes[0] ^= 0xff;
      const tampered: DelegationToken = {
        ...token,
        signature: Buffer.from(sigBytes).toString("base64"),
      };

      expect(verifyDelegation(tampered, userPubKey)).toBe(false);
    });

    test("verifies token with all optional fields", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);
      const userPubKey = encodeBase64(userKey.publicKey);

      const token = createDelegation(userKey, agentPubKey, testScope, {
        max_uses: 10,
        context_hash: "sha256-conversation-hash",
        expires_at: "2099-01-01T00:00:00.000Z",
      });

      expect(verifyDelegation(token, userPubKey)).toBe(true);
    });

    test("different scopes produce different signatures", () => {
      const userKey = generateKeyPair();
      const agentPubKey = encodeBase64(generateKeyPair().publicKey);

      const token1 = createDelegation(userKey, agentPubKey, {
        shell: { allow: ["ls"] },
      });
      const token2 = createDelegation(userKey, agentPubKey, {
        shell: { allow: ["cat"] },
      });

      expect(token1.signature).not.toBe(token2.signature);
    });
  });
});
