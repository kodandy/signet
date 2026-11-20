import nacl from "tweetnacl";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export interface KeyPair {
  publicKey: Uint8Array; // 32 bytes
  secretKey: Uint8Array; // 64 bytes
}

const SIGNET_DIR = join(homedir(), ".signet");
const USER_KEY_PATH = join(SIGNET_DIR, "user.key");

export function generateKeyPair(): KeyPair {
  const kp = nacl.sign.keyPair();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  };
}

export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, secretKey);
}

export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return nacl.sign.detached.verify(message, signature, publicKey);
  } catch {
    // tweetnacl throws on malformed inputs (wrong signature size, etc.)
    return false;
  }
}

export function encodeBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function decodeBase64(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64"));
}

// Ed25519 の群位数 L（リトルエンディアン）
const ED25519_GROUP_ORDER_LE = Uint8Array.from([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
]);

/**
 * 署名の書き方が一通りに決まる形かどうか。
 * decodeBase64 は空白やパディング欠けを読み飛ばし、tweetnacl は S に L を足した署名も受理する。
 * 同じ署名を別の文字列で書けると、署名文字列のハッシュをキーにした失効・使用回数を回避できる。
 */
export function isCanonicalSignature(signature: string): boolean {
  const bytes = decodeBase64(signature);
  if (bytes.length !== 64 || encodeBase64(bytes) !== signature) return false;
  for (let i = 31; i >= 0; i--) {
    const s = bytes[32 + i];
    const l = ED25519_GROUP_ORDER_LE[i];
    if (s !== l) return s < l;
  }
  return false;
}

export function saveKeyPair(keyPair: KeyPair, path: string = USER_KEY_PATH): void {
  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const data = JSON.stringify({
    publicKey: encodeBase64(keyPair.publicKey),
    secretKey: encodeBase64(keyPair.secretKey),
  });

  writeFileSync(path, data, { mode: 0o600 });
}

export function loadKeyPair(path: string = USER_KEY_PATH): KeyPair {
  if (!existsSync(path)) {
    throw new Error(`Key file not found: ${path}`);
  }

  const raw = readFileSync(path, "utf-8");
  const data = JSON.parse(raw) as { publicKey: string; secretKey: string };

  return {
    publicKey: decodeBase64(data.publicKey),
    secretKey: decodeBase64(data.secretKey),
  };
}

export function getSignetDir(): string {
  return SIGNET_DIR;
}
