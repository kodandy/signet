import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import type { ActionRequest } from "../engine/evaluator";
import type { ActionDecision } from "../engine/evaluator";

export interface AuditEntry {
  id: number;
  timestamp: string;
  request: ActionRequest;
  decision: ActionDecision;
  chain_hash: string;         // 前エントリのハッシュを含むチェーンハッシュ
  previous_hash: string;      // 直前エントリのchain_hash（最初は "genesis"）
}

export interface VerifyResult {
  valid: boolean;
  errors: string[];
  entries_checked: number;
}

function csvEscape(value: string): string {
  if (value.includes('"') || value.includes(",") || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return `"${value}"`;
}

const SIGNET_DIR = join(homedir(), ".signet");
const DEFAULT_DB_PATH = join(SIGNET_DIR, "audit.db");

function computeChainHash(
  previousHash: string,
  request: ActionRequest,
  decision: ActionDecision,
): string {
  const payload = JSON.stringify({ previousHash, request, decision });
  return createHash("sha256").update(payload).digest("hex");
}

export class AuditLogger {
  private db: Database.Database;

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    const dir = dirname(dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        request_json TEXT NOT NULL,
        decision_json TEXT NOT NULL,
        chain_hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL
      )
    `);

    // 使用回数カウンター（delegation token max_uses / credential max_uses）
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS usage_counter (
        key TEXT PRIMARY KEY,
        count INTEGER NOT NULL DEFAULT 0
      )
    `);

    // 無効化されたトークンの記録
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS revoked_tokens (
        token_hash TEXT PRIMARY KEY,
        revoked_at TEXT NOT NULL,
        reason TEXT
      )
    `);

    // リプレイ防止: 使用済みnonce記録
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS used_nonces (
        nonce TEXT PRIMARY KEY,
        used_at TEXT NOT NULL
      )
    `);
  }

  log(request: ActionRequest, decision: ActionDecision): AuditEntry {
    const previousHash = this.getLastHash();
    const chainHash = computeChainHash(previousHash, request, decision);
    const timestamp = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO audit_log (timestamp, request_json, decision_json, chain_hash, previous_hash)
      VALUES (?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      timestamp,
      JSON.stringify(request),
      JSON.stringify(decision),
      chainHash,
      previousHash,
    );

    return {
      id: result.lastInsertRowid as number,
      timestamp,
      request,
      decision,
      chain_hash: chainHash,
      previous_hash: previousHash,
    };
  }

  verify(): VerifyResult {
    const rows = this.db.prepare(
      "SELECT id, timestamp, request_json, decision_json, chain_hash, previous_hash FROM audit_log ORDER BY id ASC",
    ).all() as Array<{
      id: number;
      timestamp: string;
      request_json: string;
      decision_json: string;
      chain_hash: string;
      previous_hash: string;
    }>;

    const errors: string[] = [];
    let expectedPreviousHash = "genesis";

    for (const row of rows) {
      // previous_hashの連続性チェック
      if (row.previous_hash !== expectedPreviousHash) {
        errors.push(
          `Entry #${row.id}: previous_hash mismatch (expected ${expectedPreviousHash}, got ${row.previous_hash})`,
        );
      }

      // chain_hashの再計算と検証
      let request: ActionRequest;
      let decision: ActionDecision;
      try {
        request = JSON.parse(row.request_json) as ActionRequest;
        decision = JSON.parse(row.decision_json) as ActionDecision;
      } catch {
        errors.push(`Entry #${row.id}: corrupted JSON data`);
        expectedPreviousHash = row.chain_hash;
        continue;
      }
      const expectedHash = computeChainHash(row.previous_hash, request, decision);

      if (row.chain_hash !== expectedHash) {
        errors.push(
          `Entry #${row.id}: chain_hash mismatch (data may be tampered)`,
        );
      }

      expectedPreviousHash = row.chain_hash;
    }

    return {
      valid: errors.length === 0,
      errors,
      entries_checked: rows.length,
    };
  }

  exportLog(format: "json" | "csv"): string {
    const rows = this.db.prepare(
      "SELECT id, timestamp, request_json, decision_json, chain_hash, previous_hash FROM audit_log ORDER BY id ASC",
    ).all() as Array<{
      id: number;
      timestamp: string;
      request_json: string;
      decision_json: string;
      chain_hash: string;
      previous_hash: string;
    }>;

    if (format === "json") {
      const entries = rows.map((row) => ({
        id: row.id,
        timestamp: row.timestamp,
        request: JSON.parse(row.request_json),
        decision: JSON.parse(row.decision_json),
        chain_hash: row.chain_hash,
        previous_hash: row.previous_hash,
      }));
      return JSON.stringify(entries, null, 2);
    }

    // CSV
    const headers = "id,timestamp,action,target,allowed,reason,decided_by,chain_hash";
    const csvRows = rows.map((row) => {
      const req = JSON.parse(row.request_json) as ActionRequest;
      const dec = JSON.parse(row.decision_json) as ActionDecision;
      return [
        row.id,
        row.timestamp,
        req.action,
        csvEscape(req.target),
        dec.allowed,
        csvEscape(dec.reason),
        dec.decided_by,
        row.chain_hash,
      ].join(",");
    });

    return [headers, ...csvRows].join("\n");
  }

  getEntries(limit?: number): AuditEntry[] {
    const sql = limit
      ? "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?"
      : "SELECT * FROM audit_log ORDER BY id DESC";
    const rows = (limit
      ? this.db.prepare(sql).all(limit)
      : this.db.prepare(sql).all()) as Array<{
      id: number;
      timestamp: string;
      request_json: string;
      decision_json: string;
      chain_hash: string;
      previous_hash: string;
    }>;

    return rows.map((row) => ({
      id: row.id,
      timestamp: row.timestamp,
      request: JSON.parse(row.request_json) as ActionRequest,
      decision: JSON.parse(row.decision_json) as ActionDecision,
      chain_hash: row.chain_hash,
      previous_hash: row.previous_hash,
    }));
  }

  /**
   * 使用回数をインクリメントして現在のカウントを返す
   */
  incrementUsage(key: string): number {
    this.db.prepare(
      "INSERT INTO usage_counter (key, count) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET count = count + 1",
    ).run(key);

    const row = this.db.prepare(
      "SELECT count FROM usage_counter WHERE key = ?",
    ).get(key) as { count: number };
    return row.count;
  }

  /**
   * 現在の使用回数を取得
   */
  getUsageCount(key: string): number {
    const row = this.db.prepare(
      "SELECT count FROM usage_counter WHERE key = ?",
    ).get(key) as { count: number } | undefined;
    return row?.count ?? 0;
  }

  /**
   * トークンを無効化する
   */
  revokeToken(tokenHash: string, reason?: string): void {
    this.db.prepare(
      "INSERT OR REPLACE INTO revoked_tokens (token_hash, revoked_at, reason) VALUES (?, ?, ?)",
    ).run(tokenHash, new Date().toISOString(), reason ?? null);
  }

  /**
   * トークンが無効化されているかチェック
   */
  isTokenRevoked(tokenHash: string): boolean {
    const row = this.db.prepare(
      "SELECT 1 FROM revoked_tokens WHERE token_hash = ?",
    ).get(tokenHash);
    return row !== undefined;
  }

  /**
   * 無効化されたトークン一覧
   */
  listRevokedTokens(): Array<{ token_hash: string; revoked_at: string; reason: string | null }> {
    return this.db.prepare(
      "SELECT token_hash, revoked_at, reason FROM revoked_tokens ORDER BY revoked_at DESC",
    ).all() as Array<{ token_hash: string; revoked_at: string; reason: string | null }>;
  }

  /**
   * nonceが使用済みかチェック
   */
  isNonceUsed(nonce: string): boolean {
    const row = this.db.prepare(
      "SELECT 1 FROM used_nonces WHERE nonce = ?",
    ).get(nonce);
    return row !== undefined;
  }

  /**
   * nonceを使用済みとして記録
   */
  recordNonce(nonce: string): void {
    this.db.prepare(
      "INSERT OR IGNORE INTO used_nonces (nonce, used_at) VALUES (?, ?)",
    ).run(nonce, new Date().toISOString());
  }

  /**
   * 古いnonce記録をクリーンアップ（指定秒数より古いものを削除）
   */
  cleanupNonces(maxAgeSeconds: number = 600): void {
    const cutoff = new Date(Date.now() - maxAgeSeconds * 1000).toISOString();
    this.db.prepare(
      "DELETE FROM used_nonces WHERE used_at < ?",
    ).run(cutoff);
  }

  close(): void {
    this.db.close();
  }

  private getLastHash(): string {
    const row = this.db.prepare(
      "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1",
    ).get() as { chain_hash: string } | undefined;

    return row?.chain_hash ?? "genesis";
  }
}
