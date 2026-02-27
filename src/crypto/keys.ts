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
  return nacl.sign.detached.verify(message, signature, publicKey);
}

export function encodeBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function decodeBase64(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64"));
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
