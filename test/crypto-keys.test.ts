import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  generateKeyPair,
  sign,
  verify,
  encodeBase64,
  decodeBase64,
  saveKeyPair,
  loadKeyPair,
} from "../src/crypto/keys";

describe("crypto/keys", () => {
  describe("generateKeyPair", () => {
    test("generates a valid Ed25519 keypair", () => {
      const kp = generateKeyPair();

      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.secretKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey.length).toBe(32);
      expect(kp.secretKey.length).toBe(64);
    });

    test("generates unique keypairs each time", () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();

      expect(encodeBase64(kp1.publicKey)).not.toBe(encodeBase64(kp2.publicKey));
    });
  });

  describe("sign / verify", () => {
    test("signs a message and verifies with correct key", () => {
      const kp = generateKeyPair();
      const message = new TextEncoder().encode("hello signet");

      const signature = sign(message, kp.secretKey);

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
      expect(verify(message, signature, kp.publicKey)).toBe(true);
    });

    test("rejects verification with wrong public key", () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();
      const message = new TextEncoder().encode("hello signet");

      const signature = sign(message, kp1.secretKey);

      expect(verify(message, signature, kp2.publicKey)).toBe(false);
    });

    test("rejects verification with tampered message", () => {
      const kp = generateKeyPair();
      const message = new TextEncoder().encode("hello signet");
      const tampered = new TextEncoder().encode("hello tampered");

      const signature = sign(message, kp.secretKey);

      expect(verify(tampered, signature, kp.publicKey)).toBe(false);
    });

    test("rejects verification with tampered signature", () => {
      const kp = generateKeyPair();
      const message = new TextEncoder().encode("hello signet");

      const signature = sign(message, kp.secretKey);
      const tamperedSig = new Uint8Array(signature);
      tamperedSig[0] ^= 0xff;

      expect(verify(message, tamperedSig, kp.publicKey)).toBe(false);
    });
  });

  describe("encodeBase64 / decodeBase64", () => {
    test("roundtrips correctly", () => {
      const original = new Uint8Array([1, 2, 3, 255, 0, 128]);
      const encoded = encodeBase64(original);
      const decoded = decodeBase64(encoded);

      expect(decoded).toEqual(original);
    });

    test("encodes public key to stable base64", () => {
      const kp = generateKeyPair();
      const encoded = encodeBase64(kp.publicKey);

      expect(typeof encoded).toBe("string");
      expect(encoded.length).toBeGreaterThan(0);
      expect(decodeBase64(encoded)).toEqual(kp.publicKey);
    });
  });

  describe("saveKeyPair / loadKeyPair", () => {
    const testDir = join(tmpdir(), `signet-test-${Date.now()}`);
    const testKeyPath = join(testDir, "test.key");

    beforeEach(() => {
      if (!existsSync(testDir)) {
        mkdirSync(testDir, { recursive: true });
      }
    });

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("saves and loads a keypair", () => {
      const original = generateKeyPair();

      saveKeyPair(original, testKeyPath);
      const loaded = loadKeyPair(testKeyPath);

      expect(encodeBase64(loaded.publicKey)).toBe(encodeBase64(original.publicKey));
      expect(encodeBase64(loaded.secretKey)).toBe(encodeBase64(original.secretKey));
    });

    test("saved key can sign and verify", () => {
      const original = generateKeyPair();
      saveKeyPair(original, testKeyPath);
      const loaded = loadKeyPair(testKeyPath);

      const message = new TextEncoder().encode("persistence test");
      const signature = sign(message, loaded.secretKey);

      expect(verify(message, signature, loaded.publicKey)).toBe(true);
      expect(verify(message, signature, original.publicKey)).toBe(true);
    });

    test("throws when key file does not exist", () => {
      expect(() => loadKeyPair("/nonexistent/path/key.key")).toThrow(
        "Key file not found",
      );
    });

    test("creates parent directories if missing", () => {
      const nestedPath = join(testDir, "nested", "deep", "key.key");
      const kp = generateKeyPair();

      saveKeyPair(kp, nestedPath);

      expect(existsSync(nestedPath)).toBe(true);
      const loaded = loadKeyPair(nestedPath);
      expect(encodeBase64(loaded.publicKey)).toBe(encodeBase64(kp.publicKey));
    });
  });
});
