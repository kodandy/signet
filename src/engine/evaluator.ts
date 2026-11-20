import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { type KeyPair, sign, verify, encodeBase64, decodeBase64, isCanonicalSignature } from "../crypto/keys";
import { type DelegationToken, verifyDelegation } from "../crypto/delegation";
import type { Scope } from "../policy/scope";
import {
  matchFilesystem,
  matchNetwork,
  matchShell,
  matchCredential,
  type MatchResult,
} from "../policy/matcher";
import { canonicalize } from "../util/canonical";
import type { AuditLogger } from "../audit/logger";

export interface ActionRequest {
  agent_id: string;       // agent public key (base64)
  action: string;         // "shell", "fs_read", "fs_write", "net_connect", "use_credential"
  target: string;         // path, domain, command, credential name
  purpose?: string;       // LLM生成の説明
  timestamp: string;      // ISO 8601
  nonce?: string;         // ランダムな一意値（リプレイ攻撃防止）
  signature: string;      // agent key で署名 (base64)
}

// リプレイ防止: タイムスタンプの最大許容ズレ（秒）
const MAX_TIMESTAMP_DRIFT_SECONDS = 300; // 5分

// 同じリクエストは最初の使用から最大でズレ許容の 2 倍のあいだ鮮度チェックを通る。
// nonce はそれより長く残し、それを過ぎたものだけ消す。
const NONCE_RETENTION_SECONDS = MAX_TIMESTAMP_DRIFT_SECONDS * 3;

export interface ActionDecision {
  request_hash: string;
  allowed: boolean;
  reason: string;
  decided_by: "policy" | "user";
  timestamp: string;
  signature: string;      // user key で署名 (base64)
}

// ask判定時にユーザーに承認を求めるコールバック
export type AskCallback = (request: ActionRequest) => Promise<boolean>;

export interface EvaluateOptions {
  onAsk?: AskCallback;
  auditLogger?: AuditLogger;     // 使用回数カウント・トークン無効化チェック用
  context_hash?: string;          // リクエスト時のコンテキストハッシュ
}

/**
 * ActionRequestのsignature以外のフィールドからハッシュ生成
 */
function hashRequest(request: ActionRequest): string {
  const { signature: _, ...payload } = request;
  const json = canonicalize(payload);
  return createHash("sha256").update(json).digest("hex");
}

/**
 * ActionRequestの署名対象ペイロードを生成
 */
function requestPayload(request: ActionRequest): Uint8Array {
  const { signature: _, ...payload } = request;
  return new TextEncoder().encode(canonicalize(payload));
}

/**
 * ActionDecisionの署名対象ペイロードを生成
 */
function decisionPayload(decision: Omit<ActionDecision, "signature">): Uint8Array {
  return new TextEncoder().encode(canonicalize(decision));
}

function signDecision(
  decision: Omit<ActionDecision, "signature">,
  userKey: KeyPair,
): ActionDecision {
  const payload = decisionPayload(decision);
  const sig = sign(payload, userKey.secretKey);
  return { ...decision, signature: encodeBase64(sig) };
}

function makeDecision(
  requestHash: string,
  allowed: boolean,
  reason: string,
  decidedBy: "policy" | "user",
  userKey: KeyPair,
): ActionDecision {
  const partial = {
    request_hash: requestHash,
    allowed,
    reason,
    decided_by: decidedBy,
    timestamp: new Date().toISOString(),
  };
  return signDecision(partial, userKey);
}

/**
 * ActionRequest署名を生成するヘルパー（エージェント側で使用）
 * nonceが未設定の場合、自動的にランダムnonceを付与する
 */
export function signActionRequest(
  request: Omit<ActionRequest, "signature">,
  agentSecretKey: Uint8Array,
): ActionRequest {
  const withNonce = request.nonce ? request : { ...request, nonce: randomBytes(16).toString("hex") };
  const payload = new TextEncoder().encode(canonicalize(withNonce));
  const sig = sign(payload, agentSecretKey);
  return { ...withNonce, signature: encodeBase64(sig) };
}

const DUPLICATE_NONCE_REASON = "Duplicate nonce: possible replay attack";

function delegationUsageKey(delegation: DelegationToken): string {
  const tokenHash = createHash("sha256").update(delegation.signature).digest("hex");
  return `delegation:${tokenHash}`;
}

/**
 * このリクエストに掛かる max_uses を 1 回分まとめて消費する。
 * どれかが使い切られていれば何も消費せず、拒否理由を返す。
 */
function spendUses(
  auditLogger: AuditLogger,
  request: ActionRequest,
  delegation: DelegationToken,
  scope: Scope,
): string | null {
  const limits: Array<{ key: string; max: number }> = [];
  const credentialKey = `credential:${request.target}`;
  const credentialMax = request.action === "use_credential"
    ? scope.credentials?.[request.target]?.max_uses
    : undefined;
  if (credentialMax !== undefined) {
    limits.push({ key: credentialKey, max: credentialMax });
  }
  if (delegation.max_uses !== undefined) {
    limits.push({ key: delegationUsageKey(delegation), max: delegation.max_uses });
  }
  if (limits.length === 0) return null;

  const refusedKey = auditLogger.consumeUsage(limits);
  if (refusedKey === null) return null;
  return refusedKey === credentialKey && credentialMax !== undefined
    ? `Credential max_uses exceeded for ${request.target} (${credentialMax})`
    : `Delegation token max_uses exceeded (${delegation.max_uses})`;
}

/**
 * nonce を使用済みにする。すでに使われていれば false。
 * 冒頭の重複チェックと判定のあいだに同じリクエストが通ることがあるので、許可の直前にここで確定させる。
 */
function claimNonce(auditLogger: AuditLogger, nonce: string): boolean {
  const claimed = auditLogger.claimNonce(nonce);
  auditLogger.cleanupNonces(NONCE_RETENTION_SECONDS);
  return claimed;
}

/**
 * コア判定ループ
 *
 * ActionRequest受信
 *   → 署名検証（agent keyで正しく署名されてるか）
 *   → DelegationToken検証（期限切れ？）
 *   → ポリシーマッチング
 *     → blocked/deny → 即拒否
 *     → allow → 即許可
 *     → ask → コールバック → ユーザー判断
 */
export async function evaluate(
  request: ActionRequest,
  delegation: DelegationToken,
  scope: Scope,
  userKey: KeyPair,
  opts?: EvaluateOptions,
): Promise<ActionDecision> {
  const reqHash = hashRequest(request);

  // 0. タイムスタンプ鮮度チェック（リプレイ攻撃防止）
  const requestTime = new Date(request.timestamp).getTime();
  const nowMs = Date.now();
  if (isNaN(requestTime)) {
    return makeDecision(reqHash, false, "Invalid request timestamp", "policy", userKey);
  }
  const driftSeconds = Math.abs(nowMs - requestTime) / 1000;
  if (driftSeconds > MAX_TIMESTAMP_DRIFT_SECONDS) {
    return makeDecision(reqHash, false, `Request timestamp too far from current time (${Math.round(driftSeconds)}s drift, max ${MAX_TIMESTAMP_DRIFT_SECONDS}s)`, "policy", userKey);
  }

  // 0.5 Nonce重複チェック（リプレイ攻撃防止）
  if (request.nonce && opts?.auditLogger) {
    if (opts.auditLogger.isNonceUsed(request.nonce)) {
      return makeDecision(reqHash, false, DUPLICATE_NONCE_REASON, "policy", userKey);
    }
  }

  // 1. agent署名検証
  const agentPubKey = decodeBase64(request.agent_id);
  const payload = requestPayload(request);
  const sig = decodeBase64(request.signature);

  if (!verify(payload, sig, agentPubKey)) {
    return makeDecision(reqHash, false, "Invalid agent signature", "policy", userKey);
  }

  // 2. DelegationToken検証 — agent_idがsubjectと一致するか（タイミングセーフ）
  const agentIdBuf = Buffer.from(request.agent_id, "utf-8");
  const subjectBuf = Buffer.from(delegation.subject, "utf-8");
  if (agentIdBuf.length !== subjectBuf.length || !timingSafeEqual(agentIdBuf, subjectBuf)) {
    return makeDecision(reqHash, false, "Agent not authorized by delegation token", "policy", userKey);
  }

  // 3. DelegationToken署名検証 — ユーザーの実際の公開鍵で検証
  //    delegation.issuer ではなく userKey.publicKey を使う（自己署名攻撃防止）
  const userPubKeyB64 = encodeBase64(userKey.publicKey);
  if (!verifyDelegation(delegation, userPubKeyB64)) {
    return makeDecision(reqHash, false, "Invalid delegation token signature", "policy", userKey);
  }

  // 3.5 署名の書き方が一通りでないトークンは拒否する。失効と max_uses は署名文字列のハッシュで引くため
  if (!isCanonicalSignature(delegation.signature)) {
    return makeDecision(reqHash, false, "Delegation token signature is not in canonical form", "policy", userKey);
  }

  // 4. 有効期限チェック
  const now = new Date();
  if (new Date(delegation.expires_at) <= now) {
    return makeDecision(reqHash, false, "Delegation token expired", "policy", userKey);
  }

  // 4.5 トークン無効化チェック
  if (opts?.auditLogger) {
    const tokenHash = createHash("sha256")
      .update(delegation.signature)
      .digest("hex");

    if (opts.auditLogger.isTokenRevoked(tokenHash)) {
      return makeDecision(reqHash, false, "Delegation token has been revoked", "policy", userKey);
    }

    // 4.6 delegation max_uses チェック
    if (delegation.max_uses !== undefined) {
      const currentCount = opts.auditLogger.getUsageCount(delegationUsageKey(delegation));
      if (currentCount >= delegation.max_uses) {
        return makeDecision(reqHash, false, `Delegation token max_uses exceeded (${delegation.max_uses})`, "policy", userKey);
      }
    }

    // 4.7 context_hash 検証
    if (delegation.context_hash && opts.context_hash) {
      if (delegation.context_hash !== opts.context_hash) {
        return makeDecision(reqHash, false, "Context hash mismatch", "policy", userKey);
      }
    }
  }

  // 5. ポリシーマッチング
  const matchResult = matchAction(request, scope);

  if (matchResult === "deny") {
    return makeDecision(reqHash, false, `Denied by policy: ${request.action} on ${request.target}`, "policy", userKey);
  }

  if (matchResult === "allow") {
    if (opts?.auditLogger) {
      if (request.nonce && !claimNonce(opts.auditLogger, request.nonce)) {
        return makeDecision(reqHash, false, DUPLICATE_NONCE_REASON, "policy", userKey);
      }
      // credential / delegation の max_uses を確認と同時に消費する
      const exceeded = spendUses(opts.auditLogger, request, delegation, scope);
      if (exceeded !== null) {
        return makeDecision(reqHash, false, exceeded, "policy", userKey);
      }
    }

    return makeDecision(reqHash, true, `Allowed by policy: ${request.action} on ${request.target}`, "policy", userKey);
  }

  if (matchResult === "ask") {
    if (opts?.onAsk) {
      // credential max_uses チェック（ask判定のクレデンシャルにも適用）
      if (request.action === "use_credential" && opts?.auditLogger && scope.credentials) {
        const credRule = scope.credentials[request.target];
        if (credRule?.max_uses !== undefined) {
          const credKey = `credential:${request.target}`;
          const currentCount = opts.auditLogger.getUsageCount(credKey);
          if (currentCount >= credRule.max_uses) {
            return makeDecision(reqHash, false, `Credential max_uses exceeded for ${request.target} (${credRule.max_uses})`, "policy", userKey);
          }
        }
      }

      const approved = await opts.onAsk(request);
      if (approved) {
        if (opts.auditLogger) {
          // 承認待ちのあいだに同じリクエストが通っていること、別の判定が残り回数を使い切っていることがある
          if (request.nonce && !claimNonce(opts.auditLogger, request.nonce)) {
            return makeDecision(reqHash, false, DUPLICATE_NONCE_REASON, "policy", userKey);
          }
          const exceeded = spendUses(opts.auditLogger, request, delegation, scope);
          if (exceeded !== null) {
            return makeDecision(reqHash, false, exceeded, "policy", userKey);
          }
        }

        return makeDecision(reqHash, true, `Approved by user: ${request.action} on ${request.target}`, "user", userKey);
      }
      return makeDecision(reqHash, false, `Rejected by user: ${request.action} on ${request.target}`, "user", userKey);
    }
    // askコールバック未設定時はデフォルト拒否
    return makeDecision(reqHash, false, `Requires user approval (no handler): ${request.action} on ${request.target}`, "policy", userKey);
  }

  // no_match: ポリシーに定義なし → デフォルト拒否
  return makeDecision(reqHash, false, `No matching policy for: ${request.action} on ${request.target}`, "policy", userKey);
}

function matchAction(request: ActionRequest, scope: Scope): MatchResult {
  switch (request.action) {
    case "fs_read":
      return matchFilesystem(scope.filesystem, request.target, "read");
    case "fs_write":
      return matchFilesystem(scope.filesystem, request.target, "write");
    case "net_connect":
      return matchNetwork(scope.network, request.target);
    case "shell":
      return matchShell(scope.shell, request.target);
    case "use_credential":
      return matchCredential(scope.credentials, request.target, request.purpose);
    default:
      return "no_match";
  }
}

/**
 * ActionDecisionの署名を検証
 */
export function verifyDecision(
  decision: ActionDecision,
  userPubKey: string,
): boolean {
  try {
    const { signature, ...payload } = decision;
    const msg = decisionPayload(payload);
    const sig = decodeBase64(signature);
    const pubKey = decodeBase64(userPubKey);
    return verify(msg, sig, pubKey);
  } catch {
    return false;
  }
}
