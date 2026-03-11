import { timingSafeEqual } from "node:crypto";
import { type KeyPair, sign, verify, encodeBase64, decodeBase64 } from "./keys";
import type { Scope } from "../policy/scope";
import { canonicalize } from "../util/canonical";

/**
 * タイミングセーフな文字列比較（サイドチャネル攻撃防止）
 */
function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a, "utf-8");
  const bufB = Buffer.from(b, "utf-8");
  return timingSafeEqual(bufA, bufB);
}

export type { Scope };

export interface DelegationToken {
  version: 1;
  issuer: string;        // user public key (base64)
  subject: string;       // agent public key (base64)
  scope: Scope;
  issued_at: string;     // ISO 8601
  expires_at: string;    // ISO 8601
  max_uses?: number;
  context_hash?: string; // 会話コンテキストのSHA-256
  signature: string;     // issuerによる署名 (base64)
}

export interface DelegationOpts {
  expires_at?: string;     // ISO 8601。省略時はissued_atから4時間後
  max_uses?: number;
  context_hash?: string;
}

const DEFAULT_EXPIRY_MS = 4 * 60 * 60 * 1000; // 4時間

export function createDelegation(
  userKey: KeyPair,
  agentPubKey: string,
  scope: Scope,
  opts?: DelegationOpts,
): DelegationToken {
  // agentPubKeyのバリデーション
  let decoded: Uint8Array;
  try {
    decoded = decodeBase64(agentPubKey);
  } catch {
    throw new Error("Invalid agentPubKey: not valid base64");
  }
  if (decoded.length !== 32) {
    throw new Error(`Invalid agentPubKey: expected 32 bytes, got ${decoded.length}`);
  }

  const now = new Date();
  const issuedAt = now.toISOString();

  // カスタム expires_at のバリデーション
  if (opts?.expires_at !== undefined) {
    const parsed = new Date(opts.expires_at);
    if (isNaN(parsed.getTime())) {
      throw new Error("Invalid expires_at: not a valid ISO 8601 date");
    }
  }

  const defaultExpiry = new Date(now.getTime() + DEFAULT_EXPIRY_MS);
  const expiresAt = opts?.expires_at ?? defaultExpiry.toISOString();

  const payload: Omit<DelegationToken, "signature"> = {
    version: 1,
    issuer: encodeBase64(userKey.publicKey),
    subject: agentPubKey,
    scope,
    issued_at: issuedAt,
    expires_at: expiresAt,
    ...(opts?.max_uses !== undefined && { max_uses: opts.max_uses }),
    ...(opts?.context_hash !== undefined && { context_hash: opts.context_hash }),
  };

  const message = new TextEncoder().encode(canonicalize(payload));
  const sig = sign(message, userKey.secretKey);

  return {
    ...payload,
    signature: encodeBase64(sig),
  };
}

export function verifyDelegation(
  token: DelegationToken,
  userPubKey: string,
): boolean {
  // issuerとuserPubKeyの一致を検証（タイミングセーフ）
  if (!safeCompare(token.issuer, userPubKey)) {
    return false;
  }

  try {
    // signatureフィールドを除いたペイロードを復元
    const { signature, ...payload } = token;

    const message = new TextEncoder().encode(canonicalize(payload));
    const sig = decodeBase64(signature);
    const pubKey = decodeBase64(userPubKey);

    return verify(message, sig, pubKey);
  } catch {
    // 不正な base64 やデコードエラー時は検証失敗
    return false;
  }
}
