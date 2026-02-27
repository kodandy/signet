# signet MVP Architecture

## Concept

ローカルAIエージェント向けの暗号学的認可委譲レイヤー。
South et al. "Authenticated Delegation and Authorized AI Agents" (MIT, 2025) を
ローカル環境向けに軽量実装する。

**ワンライナー:** "Your agent doesn't need your keys. It needs a keyhole."

---

## Core Architecture

```
┌─────────────────────────────────────────────┐
│  User                                        │
│  Ed25519 Keypair (~/.signet/user.key)   │
└──────────┬──────────────────────────────────┘
           │ signs Delegation Token
           ▼
┌─────────────────────────────────────────────┐
│  Delegation Token (signed JSON)              │
│  ┌─────────────────────────────────────┐     │
│  │ agent_id: <agent public key>        │     │
│  │ scope:                              │     │
│  │   fs: { write: [./src/**], ... }    │     │
│  │   net: { allow: [github.com], ... } │     │
│  │   cred: { github: {uses: 5}, ... }  │     │
│  │ expires: 2026-03-01T12:00:00Z       │     │
│  │ context_hash: <conversation hash>   │     │
│  │ signature: <user signature>         │     │
│  └─────────────────────────────────────┘     │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────┐
│  signet daemon                          │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐  │
│  │ Policy    │ │ Credential│ │ Audit     │  │
│  │ Engine    │ │ Vault     │ │ Logger    │  │
│  └───────────┘ └───────────┘ └───────────┘  │
└──────────┬──────────────────────────────────┘
           │ intercepts
           ▼
┌─────────────────────────────────────────────┐
│  AI Agent (Claude Code / OpenClaw / Cursor)  │
│  Ed25519 Keypair (session-scoped)            │
│  - signs every action request                │
│  - receives signed approval/denial           │
└─────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Language | TypeScript (Bun) | Kazの主力。Bunで起動速度最適化 |
| Crypto | tweetnacl (Ed25519) | 軽量、依存ゼロ、npm最小 |
| Policy | YAML → JSON Schema | 人間が読める、バリデーション容易 |
| IPC | Unix Domain Socket | ローカル通信、ネットワーク不要 |
| Storage | SQLite (better-sqlite3) | 署名ログの永続化、ゼロ設定 |
| CLI | Commander.js | npm標準 |
| Distribution | npm (single package) | npx signet init で即使用 |

---

## Module Design

### 1. crypto/ — 鍵管理と署名

```typescript
// crypto/keys.ts
import nacl from 'tweetnacl';

interface KeyPair {
  publicKey: Uint8Array;  // 32 bytes
  secretKey: Uint8Array;  // 64 bytes
}

// ユーザー鍵: ~/.signet/user.key (暗号化保存)
// エージェント鍵: セッションごとに生成、メモリのみ

function generateKeyPair(): KeyPair;
function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
function verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
```

```typescript
// crypto/delegation.ts
interface DelegationToken {
  version: 1;
  issuer: string;          // user public key (base64)
  subject: string;         // agent public key (base64)
  scope: Scope;            // 後述
  issued_at: string;       // ISO 8601
  expires_at: string;      // ISO 8601
  max_uses?: number;       // 回数制限
  context_hash?: string;   // 会話コンテキストのSHA-256
  signature: string;       // issuerによる署名
}

function createDelegation(userKey: KeyPair, agentPubKey: string, scope: Scope, opts?: DelegationOpts): DelegationToken;
function verifyDelegation(token: DelegationToken, userPubKey: string): boolean;
```

### 2. policy/ — スコープとポリシー

```typescript
// policy/scope.ts
interface Scope {
  filesystem?: {
    writable?: string[];     // glob patterns
    readable?: string[];
    blocked?: string[];      // always deny
  };
  network?: {
    allow?: string[];        // domain whitelist
    deny?: string[];         // default: ["*"]
  };
  credentials?: {
    [name: string]: {
      allowed_actions?: string[];
      max_uses?: number;
      expires?: string;
      require_approval?: boolean;
    };
  };
  shell?: {
    allow?: string[];        // command patterns
    deny?: string[];
    ask?: string[];          // human-in-the-loop
  };
}
```

```yaml
# signet.yml — ユーザーが編集するファイル
version: 1
defaults:
  expires: "4h"               # デフォルト有効期限

scope:
  filesystem:
    writable:
      - "./src/**"
      - "./test/**"
      - "./docs/**"
    readable:
      - "./**"
    blocked:
      - "./.env"
      - "./.env.*"
      - "~/.ssh/**"
      - "~/.aws/**"

  network:
    allow:
      - "github.com"
      - "registry.npmjs.org"
      - "api.anthropic.com"
    deny:
      - "*"

  credentials:
    github_token:
      source: "env:GITHUB_TOKEN"
      allowed_actions:
        - "git push"
        - "gh pr create"
      max_uses: 10
      require_approval: false

    aws:
      source: "file:~/.aws/credentials"
      allowed_actions:
        - "aws s3 ls"
      require_approval: true

  shell:
    deny:
      - "rm -rf *"
      - "sudo *"
      - "chmod 777 *"
    ask:
      - "git push *"
      - "npm publish *"
```

### 3. engine/ — ランタイム判定

```typescript
// engine/evaluator.ts
interface ActionRequest {
  agent_id: string;          // agent public key
  action: string;            // "shell", "fs_write", "net_connect", "use_credential"
  target: string;            // path, domain, command, credential name
  purpose?: string;          // LLM生成の説明（オプション）
  timestamp: string;
  signature: string;         // agent key で署名
}

interface ActionDecision {
  request_hash: string;
  allowed: boolean;
  reason: string;
  decided_by: "policy" | "user";  // 自動判定 or 手動承認
  timestamp: string;
  signature: string;         // user key で署名（否認防止）
}

async function evaluate(
  request: ActionRequest,
  delegation: DelegationToken,
  policy: Scope
): Promise<ActionDecision>;
```

判定フロー:
```
ActionRequest受信
  → 署名検証（agent keyで正しく署名されてるか）
  → DelegationToken検証（期限切れ？回数超過？）
  → ポリシーマッチング
    → blocked/deny → 即拒否（ActionDecision署名して返却）
    → allow → 即許可（ActionDecision署名して返却）
    → ask → CLIプロンプト表示 → ユーザー判断 → ActionDecision署名して返却
  → ログ記録（request + decision、両方の署名付き）
```

### 4. vault/ — クレデンシャル隔離

```typescript
// vault/manager.ts

// activate時:
//   1. .envを ~/.signet/vault/ に退避（暗号化）
//   2. 環境変数からクレデンシャルを除去
//   3. エージェントのプロセスにはクレデンシャルが見えない
//
// クレデンシャル使用時:
//   1. エージェントがuse_credentialリクエスト送信
//   2. ポリシー判定（allowed_actions, max_uses, require_approval）
//   3. 許可 → 一時的に環境変数に注入 → コマンド実行 → 即除去
//   4. 全操作を署名付きログに記録

function activate(config: VaultConfig): void;
function deactivate(): void;
function injectForCommand(credName: string, command: string): ChildProcess;
```

### 5. audit/ — 署名付きログ

```typescript
// audit/logger.ts

// SQLite に全操作を記録
// 各レコード: request JSON + request署名 + decision JSON + decision署名
// → 改竄不可能な監査証跡

interface AuditEntry {
  id: number;
  timestamp: string;
  request: ActionRequest;      // agent署名付き
  decision: ActionDecision;    // user署名付き
}

// チェーンハッシュ: 各エントリが前エントリのハッシュを含む
// → ログの挿入・削除・改竄が検出可能

function log(request: ActionRequest, decision: ActionDecision): void;
function verify(): { valid: boolean; errors: string[] };
function export(format: "json" | "csv"): string;
```

### 6. adapters/ — エージェント統合

```typescript
// adapters/claude-code.ts
// signet init --claude-code 時に:
//   1. .claude/settings.json にdeny/askルール注入
//   2. CLAUDE.md にセキュリティポリシー追記
//   3. signetデーモンへのUDS接続設定

// adapters/openclaw.ts
// OpenClawのconfig.yamlに制限を注入

// adapters/generic.ts
// PATH差し替え + 環境変数プロキシ（汎用）
```

---

## CLI Interface

```bash
# セットアップ
signet init                    # 対話式。鍵生成 + signet.yml生成
signet init --claude-code      # Claude Code adapter込み
signet init --template node    # Node.jsテンプレート

# 運用
signet activate                # daemon起動 + vault有効化 + adapter適用
signet deactivate              # 元に戻す
signet status                  # 現在の状態表示

# 監査
signet log                     # 今日の操作ログ
signet log --verify            # 全署名チェーン検証
signet log --export json       # エクスポート

# 鍵管理
signet keys list               # 登録済みエージェント鍵一覧
signet keys revoke <agent_id>  # エージェント鍵失効

# デバッグ
signet check "git push origin main"   # ドライラン判定
```

---

## MVP Scope (2 weeks)

### Week 1: Core
- [ ] crypto/ — Ed25519鍵生成、署名、検証
- [ ] policy/ — YAMLパーサー、Scope構造体
- [ ] engine/ — ActionRequest評価、CLI承認プロンプト
- [ ] vault/ — .env退避、環境変数クレデンシャル隔離
- [ ] audit/ — SQLiteログ、チェーンハッシュ

### Week 2: UX + Integration
- [ ] CLI — init, activate, deactivate, log, check
- [ ] adapters/claude-code — settings.json + CLAUDE.md生成
- [ ] adapters/generic — PATH差し替え
- [ ] テンプレート — node, python, general
- [ ] README — デモGIF、South et al.引用、アーキテクチャ図
- [ ] npm publish

### Post-MVP (Phase 2)
- [ ] 自然言語→構造化パーミッション自動変換（LLM活用）
- [ ] OpenClaw / Cursor adapter
- [ ] Slack/webhook承認フロー
- [ ] Web UIダッシュボード

### Phase 3 (マルチエージェント対応)
- [ ] DID/VC統合（W3C標準）
- [ ] エージェント間委任チェーン
- [ ] ERC-8004互換
- [ ] 選択的開示

---

## File Structure

```
signet/
├── package.json
├── tsconfig.json
├── README.md
├── LICENSE                   # MIT
├── src/
│   ├── index.ts              # CLI entry point
│   ├── crypto/
│   │   ├── keys.ts           # Ed25519 keypair management
│   │   └── delegation.ts     # Delegation token creation/verification
│   ├── policy/
│   │   ├── parser.ts         # YAML → Scope
│   │   ├── matcher.ts        # glob/pattern matching
│   │   └── templates/        # node.yml, python.yml, general.yml
│   ├── engine/
│   │   ├── evaluator.ts      # Core decision engine
│   │   ├── daemon.ts         # UDS server
│   │   └── prompt.ts         # CLI approval UI
│   ├── vault/
│   │   ├── manager.ts        # Credential isolation
│   │   └── injector.ts       # Temp credential injection
│   ├── audit/
│   │   ├── logger.ts         # SQLite + chain hash
│   │   └── verifier.ts       # Log integrity check
│   └── adapters/
│       ├── claude-code.ts
│       ├── openclaw.ts
│       └── generic.ts
├── templates/
│   ├── node.yml
│   ├── python.yml
│   └── general.yml
└── test/
    ├── crypto.test.ts
    ├── policy.test.ts
    ├── engine.test.ts
    └── vault.test.ts
```

---

## Security Model

### 脅威モデル
1. **プロンプトインジェクション** → エージェントが悪意ある操作を実行
   - 対策: 全操作がDelegation Tokenのスコープ内かチェック
2. **クレデンシャル窃取** → エージェントが.envやSSH鍵を外部送信
   - 対策: vault退避 + network fenceでexfiltration防止
3. **ログ改竄** → 事後的に操作履歴を書き換え
   - 対策: チェーンハッシュ + 双方署名
4. **エージェント偽装** → 別のエージェントが権限を利用
   - 対策: セッション鍵ペアで各エージェントを識別

### 信頼境界
- **信頼する**: ユーザーのマシン、signetデーモン
- **信頼しない**: AIエージェント、LLM、外部ネットワーク

---

## Differentiation

| | Sandbox (Claude Code) | Cerbos/Permit.io | 1Password | **signet** |
|---|---|---|---|---|
| 思想 | 閉じ込め | ポリシーエンジン | 鍵の金庫 | **暗号学的委譲** |
| 対象 | 単一エージェント | エンタープライズ | ブラウザ | **ローカル全般** |
| セットアップ | 環境設定 | Docker+IdP | SaaS契約 | **npx init** |
| 暗号署名 | なし | なし | 部分的 | **全操作** |
| 否認防止 | なし | なし | なし | **あり** |
| コンテキスト判定 | なし | 属性ベース | なし | **会話ベース** |
| マルチエージェント | ✕ | ○ | ✕ | **○（Phase 3）** |

---

## References

- South, T. et al. "Authenticated Delegation and Authorized AI Agents" (2025) arXiv:2501.09674
- Rodriguez Garzon, S. et al. "AI Agents with DIDs and VCs" (2025) arXiv:2511.02841
- ERC-8004: Trustless Agents (2025) EIP-8004
- Anthropic "Claude Code Sandboxing" (2026)
