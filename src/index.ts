#!/usr/bin/env node
import { Command } from "commander";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";

import { generateKeyPair, saveKeyPair, loadKeyPair, encodeBase64, decodeBase64 } from "./crypto/keys";
import { createDelegation } from "./crypto/delegation";
import { parsePolicyFile } from "./policy/parser";
import {
  matchShell, matchFilesystem, matchNetwork, matchCredential, type MatchResult,
  matchShellDetailed, matchFilesystemDetailed, matchNetworkDetailed, matchCredentialDetailed,
  type MatchDetail,
} from "./policy/matcher";
import { AuditLogger } from "./audit/logger";
import { activate, deactivate, getVaultState } from "./vault/manager";
import { generateClaudeCodeSettings } from "./adapters/claude-code";
import { generateWrappers, generatePathSetup } from "./adapters/generic";
import { generateCursorSettings } from "./adapters/cursor";

const SIGNET_DIR = join(homedir(), ".signet");

const program = new Command();

program
  .name("signet")
  .description("Cryptographic authorization delegation layer for local AI agents")
  .version("0.1.0");

// ─── signet init ───
program
  .command("init")
  .description("Initialize signet: generate keys and create signet.yml (Example: signet init --smart, signet init --template node)")
  .option("--template <name>", "Use a preset template (node, python, general)")
  .option("--smart", "Auto-detect project type and generate tailored policy")
  .option("--claude-code", "Generate Claude Code adapter settings")
  .action((opts) => {
    // 1. ~/.signet/ ディレクトリ作成
    if (!existsSync(SIGNET_DIR)) {
      mkdirSync(SIGNET_DIR, { recursive: true, mode: 0o700 });
    }

    // 2. ユーザー鍵ペア生成
    const userKeyPath = join(SIGNET_DIR, "user.key");
    if (existsSync(userKeyPath)) {
      console.log("User keypair already exists at", userKeyPath);
    } else {
      const kp = generateKeyPair();
      saveKeyPair(kp, userKeyPath);
      console.log("Generated user keypair");
      console.log("  Public key:", encodeBase64(kp.publicKey));
    }

    // 3. signet.yml生成
    const configPath = resolve("signet.yml");
    if (existsSync(configPath)) {
      console.log("signet.yml already exists");
    } else if (opts.smart) {
      // --smart: プロジェクト自動検出
      const result = detectProject(process.cwd());
      writeFileSync(configPath, result.yml);
      console.log(`Created signet.yml (auto-detected: ${result.type})`);
      for (const note of result.notes) {
        console.log(`  ${note}`);
      }
    } else {
      const template = opts.template || "general";
      const validTemplates = ["general", "node", "python"];
      if (!validTemplates.includes(template)) {
        console.error(`Error: Unknown template "${template}". Available: ${validTemplates.join(", ")}`);
        process.exit(1);
      }
      const templatePath = join(__dirname, "..", "templates", `${template}.yml`);
      if (existsSync(templatePath)) {
        const tpl = readFileSync(templatePath, "utf-8");
        writeFileSync(configPath, tpl);
        console.log(`Created signet.yml (template: ${template})`);
      } else {
        writeFileSync(configPath, generateDefaultConfig());
        console.log("Created signet.yml (default)");
      }
    }

    // 4. Claude Code adapter（オプション）
    if (opts.claudeCode) {
      const config = parsePolicyFile(resolve("signet.yml"));
      generateClaudeCodeSettings(config.scope, process.cwd());
      console.log("Claude Code adapter configured (.claude/settings.json + CLAUDE.md)");
    }

    console.log("\nSetup complete. Edit signet.yml to customize your policy.");
    console.log("Run 'signet activate' to start protecting your project.");
  });

// ─── signet activate ───
program
  .command("activate")
  .description("Activate vault protection and apply policies")
  .action(() => {
    try {
      const configPath = resolve("signet.yml");
      if (!existsSync(configPath)) {
        console.error("Error: signet.yml not found. Run 'signet init' first.");
        process.exit(1);
      }

      // ポリシーからクレデンシャル環境変数を抽出
      const config = parsePolicyFile(configPath);
      const credentialEnvVars: string[] = [];
      if (config.scope.credentials) {
        for (const [, rule] of Object.entries(config.scope.credentials)) {
          if (rule.source?.startsWith("env:")) {
            credentialEnvVars.push(rule.source.slice(4));
          }
        }
      }

      const state = activate({
        projectDir: process.cwd(),
        credentialEnvVars: credentialEnvVars.length > 0 ? credentialEnvVars : undefined,
      });
      console.log("Vault activated");
      if (state.evacuatedFiles.length > 0) {
        console.log("  Evacuated files:", state.evacuatedFiles.join(", "));
      }
      if (state.evacuatedVars.length > 0) {
        console.log("  Evacuated env vars:", state.evacuatedVars.join(", "));
      }
      if (state.evacuatedFiles.length === 0 && state.evacuatedVars.length === 0) {
        console.log("  No .env files or credential env vars found to protect.");
      }
      console.log("\nNext: signet status");
    } catch (err: unknown) {
      console.error("Error:", err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

// ─── signet deactivate ───
program
  .command("deactivate")
  .description("Deactivate vault and restore credentials")
  .option("--force", "Force deactivate even if restoration fails (use when vault is stuck)")
  .action((opts) => {
    try {
      const state = deactivate({ force: opts.force }) as any;
      if (opts.force && state.warnings?.length) {
        console.log("Vault force-deactivated with warnings:");
        for (const w of state.warnings) {
          console.log(`  \u26A0\uFE0F  ${w}`);
        }
      } else {
        console.log("Vault deactivated");
        if (state.evacuatedFiles.length > 0) {
          console.log("  Restored files:", state.evacuatedFiles.join(", "));
        }
      }
      console.log("\nCredentials restored. Run 'signet activate' to re-protect.");
    } catch (err: unknown) {
      console.error("Error:", err instanceof Error ? err.message : String(err));
      if (!opts.force) {
        console.error("Hint: Use --force to clear vault state even if restoration fails.");
      }
      process.exit(1);
    }
  });

// ─── signet status ───
program
  .command("status")
  .description("Show current signet status and setup checklist")
  .action(() => {
    const userKeyPath = join(SIGNET_DIR, "user.key");
    const configPath = resolve("signet.yml");
    const vaultState = getVaultState();

    const hasKey = existsSync(userKeyPath);
    const hasPolicy = existsSync(configPath);
    const isVaultActive = vaultState?.active ?? false;
    const agentsDir = join(SIGNET_DIR, "agents");
    const agentFiles = existsSync(agentsDir)
      ? (readdirSync(agentsDir) as string[]).filter((f: string) => f.endsWith(".pub"))
      : [];

    console.log("\nsignet status\n");

    // Checklist
    console.log(`  ${hasKey ? "\u2705" : "\u274C"} User keypair     ${hasKey ? "configured" : "run: signet init"}`);
    console.log(`  ${hasPolicy ? "\u2705" : "\u274C"} Policy file      ${hasPolicy ? "signet.yml" : "run: signet init"}`);
    console.log(`  ${isVaultActive ? "\u2705" : "\u26A0\uFE0F"} Vault            ${isVaultActive ? "active" : "inactive — run: signet activate"}`);
    console.log(`  ${agentFiles.length > 0 ? "\u2705" : "\u2796"} Agent keys       ${agentFiles.length > 0 ? `${agentFiles.length} registered` : "none — run: signet delegate <pubkey>"}`);

    if (hasKey) {
      const kp = loadKeyPair(userKeyPath);
      console.log(`\n  Public key: ${encodeBase64(kp.publicKey)}`);
    }

    if (isVaultActive && vaultState) {
      if (vaultState.evacuatedFiles.length > 0) {
        console.log(`  Protected: ${vaultState.evacuatedFiles.join(", ")}`);
      }
    }

    if (hasPolicy) {
      try {
        const config = parsePolicyFile(configPath);
        const s = config.scope;
        const counts = [];
        if (s.shell) {
          const n = (s.shell.allow?.length ?? 0) + (s.shell.deny?.length ?? 0) + (s.shell.ask?.length ?? 0);
          counts.push(`${n} shell`);
        }
        if (s.filesystem) {
          const n = (s.filesystem.writable?.length ?? 0) + (s.filesystem.readable?.length ?? 0) + (s.filesystem.blocked?.length ?? 0);
          counts.push(`${n} filesystem`);
        }
        if (s.network) {
          const n = (s.network.allow?.length ?? 0) + (s.network.deny?.length ?? 0);
          counts.push(`${n} network`);
        }
        if (s.credentials) {
          counts.push(`${Object.keys(s.credentials).length} credential`);
        }
        if (counts.length > 0) {
          console.log(`  Policy rules: ${counts.join(", ")}`);
        }
      } catch {
        console.log("  Policy: error parsing signet.yml");
      }
    }

    console.log();
  });

// ─── signet log ───
program
  .command("log")
  .description("View audit log (Examples: signet log -n 20, signet log --verify, signet log --export json)")
  .option("--verify", "Verify chain hash integrity")
  .option("--export <format>", "Export log (json or csv)")
  .option("-n, --limit <count>", "Number of entries to show", "10")
  .action((opts) => {
    const logger = new AuditLogger();

    if (opts.verify) {
      const result = logger.verify();
      if (result.valid) {
        console.log(`Chain verified: ${result.entries_checked} entries, all valid.`);
      } else {
        console.error(`Chain BROKEN: ${result.errors.length} error(s) found:`);
        for (const err of result.errors) {
          console.error("  -", err);
        }
        process.exit(1);
      }
      logger.close();
      return;
    }

    if (opts.export) {
      const output = logger.exportLog(opts.export as "json" | "csv");
      console.log(output);
      logger.close();
      return;
    }

    const entries = logger.getEntries(parseInt(opts.limit));
    if (entries.length === 0) {
      console.log("No audit log entries.");
    } else {
      for (const entry of entries.reverse()) {
        const icon = entry.decision.allowed ? "\u2705" : "\u274C";
        console.log(
          `${icon} [${entry.timestamp}] ${entry.request.action} ${entry.request.target} — ${entry.decision.reason}`,
        );
      }
    }
    logger.close();
  });

// ─── signet check ───
program
  .command("check <target>")
  .description("Dry-run policy check (Examples: signet check \"npm test\", signet check --type fs_write ./src/index.ts)")
  .option("-t, --type <type>", "Resource type: shell, fs_read, fs_write, network, credential (default: shell)")
  .option("--purpose <purpose>", "Purpose string for credential checks")
  .action((target: string, opts) => {
    const configPath = resolve("signet.yml");
    if (!existsSync(configPath)) {
      console.error("Error: signet.yml not found. Run 'signet init' first.");
      process.exit(1);
    }

    const config = parsePolicyFile(configPath);
    const scope = config.scope;
    const type = opts.type || "shell";

    let detail: MatchDetail;
    let label: string;

    switch (type) {
      case "shell":
        detail = matchShellDetailed(scope.shell, target);
        label = `shell: "${target}"`;
        break;
      case "fs_read":
        detail = matchFilesystemDetailed(scope.filesystem, target, "read");
        label = `fs_read: ${target}`;
        break;
      case "fs_write":
        detail = matchFilesystemDetailed(scope.filesystem, target, "write");
        label = `fs_write: ${target}`;
        break;
      case "network":
        detail = matchNetworkDetailed(scope.network, target);
        label = `network: ${target}`;
        break;
      case "credential":
        detail = matchCredentialDetailed(scope.credentials, target, opts.purpose);
        label = `credential: ${target}${opts.purpose ? ` (${opts.purpose})` : ""}`;
        break;
      default:
        console.error(`Error: Unknown type "${type}". Use: shell, fs_read, fs_write, network, credential`);
        process.exit(1);
    }

    // no_match → engine treats as deny (deny-by-default)
    const effectiveResult = detail.result === "no_match" ? "deny" : detail.result;
    const icon = effectiveResult === "allow" ? "\u2705" : effectiveResult === "deny" ? "\u274C" : "\u2753";

    let output = `${icon} ${label} → ${effectiveResult}`;
    if (detail.matchedRule) {
      output += `  (matched: "${detail.matchedRule}" in ${detail.matchedIn})`;
    } else if (detail.result === "no_match") {
      output += "  (no matching rule — denied by default)";
    } else if (detail.matchedIn) {
      output += `  (${detail.matchedIn})`;
    }
    console.log(output);
  });

// ─── signet delegate ───
program
  .command("delegate <agent-pubkey>")
  .description("Issue a delegation token to an agent (Example: signet delegate <base64-pubkey> --expires 2h)")
  .option("--expires <duration>", "Token lifetime: e.g. 1h, 4h, 24h (default: 4h)", "4h")
  .option("--max-uses <count>", "Maximum number of uses")
  .option("--context-hash <hash>", "Bind token to a specific context hash")
  .option("-o, --output <file>", "Write token to file instead of stdout")
  .action((agentPubKey: string, opts) => {
    const userKeyPath = join(SIGNET_DIR, "user.key");
    if (!existsSync(userKeyPath)) {
      console.error("Error: User keypair not found. Run 'signet init' first.");
      process.exit(1);
    }

    const configPath = resolve("signet.yml");
    if (!existsSync(configPath)) {
      console.error("Error: signet.yml not found. Run 'signet init' first.");
      process.exit(1);
    }

    // Parse duration string → expires_at ISO string
    const durationMs = parseDuration(opts.expires);
    if (durationMs === null) {
      console.error(`Error: Invalid duration "${opts.expires}". Use format like: 1h, 4h, 30m, 24h`);
      process.exit(1);
    }

    const userKey = loadKeyPair(userKeyPath);
    const config = parsePolicyFile(configPath);

    try {
      const token = createDelegation(userKey, agentPubKey, config.scope, {
        expires_at: new Date(Date.now() + durationMs).toISOString(),
        max_uses: opts.maxUses ? parseInt(opts.maxUses) : undefined,
        context_hash: opts.contextHash,
      });

      const tokenJson = JSON.stringify(token, null, 2);

      if (opts.output) {
        writeFileSync(opts.output, tokenJson, { mode: 0o600 });
        console.log(`Token written to ${opts.output}`);
      } else {
        console.log(tokenJson);
      }

      // トークンメタデータを保存（リスト表示用）
      const tokensDir = join(SIGNET_DIR, "tokens");
      if (!existsSync(tokensDir)) {
        mkdirSync(tokensDir, { recursive: true, mode: 0o700 });
      }
      const sigHash = createHash("sha256").update(token.signature).digest("hex");
      const meta = {
        signature_hash: sigHash,
        subject: token.subject,
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        max_uses: token.max_uses,
      };
      writeFileSync(join(tokensDir, `${sigHash.slice(0, 16)}.json`), JSON.stringify(meta, null, 2), { mode: 0o600 });

      // Summary to stderr so it doesn't pollute JSON output when piped
      const expiresAt = new Date(token.expires_at);
      console.error(`\nDelegation issued:`);
      console.error(`  Subject: ${agentPubKey.substring(0, 16)}...`);
      console.error(`  Expires: ${expiresAt.toLocaleString()}`);
      if (token.max_uses) console.error(`  Max uses: ${token.max_uses}`);
      if (token.context_hash) console.error(`  Context: ${token.context_hash.substring(0, 16)}...`);
    } catch (err: unknown) {
      console.error("Error:", err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

// ─── signet keys ───
const keysCmd = program
  .command("keys")
  .description("Manage agent keys");

keysCmd
  .command("list")
  .description("List registered agent keys")
  .action(() => {
    const agentsDir = join(SIGNET_DIR, "agents");
    if (!existsSync(agentsDir)) {
      console.log("No registered agent keys.");
      return;
    }

    const files = readdirSync(agentsDir) as string[];
    if (files.length === 0) {
      console.log("No registered agent keys.");
      return;
    }

    for (const file of files) {
      if (file.endsWith(".pub")) {
        const pubKey = readFileSync(join(agentsDir, file), "utf-8").trim();
        console.log(`  ${file.replace(".pub", "")}: ${pubKey}`);
      }
    }
  });

keysCmd
  .command("generate <name>")
  .description("Generate a new agent keypair (Example: signet keys generate claude-code)")
  .action((name: string) => {
    const agentsDir = join(SIGNET_DIR, "agents");
    if (!existsSync(agentsDir)) {
      mkdirSync(agentsDir, { recursive: true, mode: 0o700 });
    }

    const keyPath = join(agentsDir, `${name}.key`);
    const pubPath = join(agentsDir, `${name}.pub`);
    if (existsSync(keyPath) || existsSync(pubPath)) {
      console.error(`Error: Agent "${name}" already exists. Remove files in ${agentsDir} first to regenerate.`);
      process.exit(1);
    }

    const kp = generateKeyPair();
    saveKeyPair(kp, keyPath);
    const pubB64 = encodeBase64(kp.publicKey);
    writeFileSync(pubPath, pubB64 + "\n", { mode: 0o644 });

    console.log(`Generated agent keypair: ${name}`);
    console.log(`  Private key: ${keyPath}`);
    console.log(`  Public key:  ${pubB64}`);
    console.log(`\nNext: signet delegate ${pubB64}`);
  });

keysCmd
  .command("register <name> <pubkey>")
  .description("Register an agent's public key (Example: signet keys register claude-code <base64-pubkey>)")
  .action((name: string, pubkey: string) => {
    // Validate base64 pubkey
    try {
      const decoded = decodeBase64(pubkey);
      if (decoded.length !== 32) {
        console.error(`Error: Invalid public key — expected 32 bytes, got ${decoded.length}`);
        process.exit(1);
      }
    } catch {
      console.error("Error: Invalid public key — not valid base64");
      process.exit(1);
    }

    const agentsDir = join(SIGNET_DIR, "agents");
    if (!existsSync(agentsDir)) {
      mkdirSync(agentsDir, { recursive: true, mode: 0o700 });
    }

    const keyPath = join(agentsDir, `${name}.pub`);
    if (existsSync(keyPath)) {
      console.error(`Error: Agent "${name}" already registered. Remove ${keyPath} first to re-register.`);
      process.exit(1);
    }

    writeFileSync(keyPath, pubkey + "\n", { mode: 0o644 });
    console.log(`Registered agent key: ${name}`);
    console.log(`  Public key: ${pubkey.substring(0, 24)}...`);
    console.log(`\nNext: signet delegate ${pubkey}`);
  });

// ─── signet tokens ───
const tokensCmd = program
  .command("tokens")
  .description("Manage delegation tokens");

tokensCmd
  .command("list")
  .description("List issued delegation tokens")
  .action(() => {
    const tokensDir = join(SIGNET_DIR, "tokens");
    if (!existsSync(tokensDir)) {
      console.log("No delegation tokens issued yet.");
      console.log("\nNext: signet delegate <pubkey>");
      return;
    }

    const files = (readdirSync(tokensDir) as string[]).filter((f: string) => f.endsWith(".json"));
    if (files.length === 0) {
      console.log("No delegation tokens issued yet.");
      console.log("\nNext: signet delegate <pubkey>");
      return;
    }

    const logger = new AuditLogger();
    const now = new Date();

    console.log("\nIssued delegation tokens:\n");
    for (const file of files) {
      const meta = JSON.parse(readFileSync(join(tokensDir, file), "utf-8"));
      const expires = new Date(meta.expires_at);
      const expired = expires < now;
      const revoked = logger.isTokenRevoked(meta.signature_hash);

      let status = "\u2705 active";
      if (revoked) status = "\u274C revoked";
      else if (expired) status = "\u23F0 expired";

      // エージェント名を逆引き
      const agentsDir = join(SIGNET_DIR, "agents");
      let agentName = meta.subject.substring(0, 16) + "...";
      if (existsSync(agentsDir)) {
        for (const af of readdirSync(agentsDir) as string[]) {
          if (af.endsWith(".pub")) {
            const pubKey = readFileSync(join(agentsDir, af), "utf-8").trim();
            if (pubKey === meta.subject) {
              agentName = af.replace(".pub", "");
              break;
            }
          }
        }
      }

      console.log(`  ${status}  ${agentName}  issued ${meta.issued_at.slice(0, 16)}  expires ${meta.expires_at.slice(0, 16)}  sig:${meta.signature_hash.substring(0, 12)}...`);
    }

    logger.close();
    console.log();
  });

// ─── signet revoke ───
program
  .command("revoke <token-signature>")
  .description("Revoke a delegation token (Example: signet revoke <base64-signature> --reason 'compromised')")
  .option("--reason <reason>", "Reason for revocation")
  .action((tokenSig: string, opts) => {
    const logger = new AuditLogger();

    // signature → SHA-256 hash（既にhex形式の場合はそのまま使用）
    const tokenHash = /^[a-f0-9]{64}$/.test(tokenSig)
      ? tokenSig
      : createHash("sha256").update(tokenSig).digest("hex");

    if (logger.isTokenRevoked(tokenHash)) {
      console.log("Token is already revoked.");
      logger.close();
      return;
    }

    logger.revokeToken(tokenHash, opts.reason);
    console.log(`Token revoked: ${tokenHash.substring(0, 16)}...`);
    if (opts.reason) {
      console.log(`  Reason: ${opts.reason}`);
    }
    logger.close();
  });

// ─── signet revoked ───
program
  .command("revoked")
  .description("List revoked delegation tokens")
  .action(() => {
    const logger = new AuditLogger();
    const tokens = logger.listRevokedTokens();

    if (tokens.length === 0) {
      console.log("No revoked tokens.");
    } else {
      for (const t of tokens) {
        console.log(`  ${t.token_hash.substring(0, 16)}... revoked at ${t.revoked_at}${t.reason ? ` (${t.reason})` : ""}`);
      }
    }
    logger.close();
  });

// ─── signet scan ───
program
  .command("scan")
  .description("Scan project for exposed credentials and security risks")
  .option("--fix", "Automatically add found files to signet.yml blocked list")
  .action((opts) => {
    const projectDir = process.cwd();

    // 既知のクレデンシャルファイルパターン
    const credentialPatterns = [
      { glob: ".env", desc: "Environment variables" },
      { glob: ".env.local", desc: "Local environment variables" },
      { glob: ".env.production", desc: "Production environment variables" },
      { glob: ".env.development", desc: "Development environment variables" },
      { glob: ".env.*", desc: "Environment variable variants" },
    ];

    const sensitivePatterns = [
      { glob: "**/*.pem", desc: "PEM certificates/keys" },
      { glob: "**/*.key", desc: "Private keys" },
      { glob: "**/*.p12", desc: "PKCS#12 keystores" },
      { glob: "**/credentials.json", desc: "Service account credentials" },
      { glob: "**/service-account*.json", desc: "Service account files" },
      { glob: "**/.htpasswd", desc: "HTTP password files" },
      { glob: "**/id_rsa", desc: "SSH private keys" },
      { glob: "**/id_ed25519", desc: "SSH private keys (Ed25519)" },
    ];

    const dangerousDirs = [
      { path: ".aws", desc: "AWS credentials" },
      { path: ".ssh", desc: "SSH keys" },
      { path: ".gnupg", desc: "GPG keys" },
      { path: ".docker", desc: "Docker credentials" },
    ];

    const found: { file: string; desc: string; severity: "high" | "medium" }[] = [];

    // .envファイルチェック
    for (const p of credentialPatterns) {
      // .env.* のワイルドカード展開
      if (p.glob.includes("*")) {
        try {
          const dir = readdirSync(projectDir) as string[];
          for (const f of dir) {
            if (f.startsWith(".env.") && f !== ".env.example" && f !== ".env.sample" && f !== ".env.template") {
              if (existsSync(join(projectDir, f))) {
                found.push({ file: `./${f}`, desc: p.desc, severity: "high" });
              }
            }
          }
        } catch { /* ignore */ }
      } else {
        const fullPath = join(projectDir, p.glob);
        if (existsSync(fullPath)) {
          found.push({ file: `./${p.glob}`, desc: p.desc, severity: "high" });
        }
      }
    }

    // ホームディレクトリの危険なディレクトリチェック
    for (const d of dangerousDirs) {
      const fullPath = join(homedir(), d.path);
      if (existsSync(fullPath)) {
        found.push({ file: `~/${d.path}`, desc: d.desc, severity: "medium" });
      }
    }

    // プロジェクト内のセンシティブファイルチェック（1階層のみ高速スキャン）
    for (const p of sensitivePatterns) {
      if (!p.glob.startsWith("**/")) continue;
      const fileName = p.glob.replace("**/", "");
      if (fileName.includes("*")) continue; // ワイルドカードはスキップ
      const fullPath = join(projectDir, fileName);
      if (existsSync(fullPath)) {
        found.push({ file: `./${fileName}`, desc: p.desc, severity: "high" });
      }
    }

    console.log("\nsignet scan\n");

    if (found.length === 0) {
      console.log("  No exposed credentials found. Your project looks clean.");
    } else {
      const high = found.filter(f => f.severity === "high");
      const medium = found.filter(f => f.severity === "medium");

      if (high.length > 0) {
        console.log("  \u{1F6A8} Exposed in project:");
        for (const f of high) {
          console.log(`    ${f.file} — ${f.desc}`);
        }
      }

      if (medium.length > 0) {
        console.log("  \u26A0\uFE0F  Accessible from home directory:");
        for (const f of medium) {
          console.log(`    ${f.file} — ${f.desc}`);
        }
      }

      // ポリシーとの照合
      const configPath = resolve("signet.yml");
      if (existsSync(configPath)) {
        try {
          const config = parsePolicyFile(configPath);
          const blocked = config.scope.filesystem?.blocked ?? [];
          const unprotected = high.filter(f =>
            !blocked.some(b => f.file === b || f.file.replace("./", "") === b.replace("./", "")),
          );
          if (unprotected.length > 0) {
            console.log("\n  \u274C Not in signet.yml blocked list:");
            for (const f of unprotected) {
              console.log(`    ${f.file}`);
            }
            if (opts.fix) {
              // signet.yml に blocked パスを追加
              let yml = readFileSync(configPath, "utf-8");
              for (const f of unprotected) {
                const pattern = f.file.startsWith("./") ? f.file : `./${f.file}`;
                if (!yml.includes(pattern)) {
                  // blocked: セクションの末尾に追加
                  yml = yml.replace(
                    /(blocked:\n(?:\s+- .*\n)*)/,
                    `$1      - "${pattern}"\n`,
                  );
                }
              }
              writeFileSync(configPath, yml);
              console.log("\n  \u2705 Added to signet.yml blocked list. Re-run 'signet adapt claude-code' to update.");
            } else {
              console.log("\n  Hint: Run 'signet scan --fix' to add them automatically.");
            }
          } else if (high.length > 0) {
            console.log("\n  \u2705 All found files are in signet.yml blocked list.");
          }
        } catch { /* ignore parse errors */ }
      }

      // vault状態チェック
      const vaultState = getVaultState();
      if (vaultState?.active) {
        const evacuated = new Set(vaultState.evacuatedFiles);
        const notEvacuated = high.filter(f => {
          const abs = resolve(projectDir, f.file);
          return !evacuated.has(abs);
        });
        if (notEvacuated.length > 0) {
          console.log(`\n  \u26A0\uFE0F  Vault active but these files are not evacuated:`);
          for (const f of notEvacuated) {
            console.log(`    ${f.file}`);
          }
        }
      } else if (high.length > 0) {
        console.log("\n  Hint: Run 'signet activate' to evacuate .env files to encrypted vault.");
      }
    }

    console.log();
  });

// ─── signet adapt ───
const adaptCmd = program
  .command("adapt")
  .description("Generate adapter settings for a specific agent");

adaptCmd
  .command("claude-code")
  .description("Generate Claude Code settings from signet.yml")
  .option("--project-dir <dir>", "Project directory", process.cwd())
  .action((opts) => {
    const configPath = resolve("signet.yml");
    if (!existsSync(configPath)) {
      console.error("Error: signet.yml not found. Run 'signet init' first.");
      process.exit(1);
    }

    const config = parsePolicyFile(configPath);
    generateClaudeCodeSettings(config.scope, opts.projectDir);
    console.log("Claude Code adapter configured:");
    console.log("  .claude/settings.json — permissions updated");
    console.log("  CLAUDE.md — security policy section added");
  });

adaptCmd
  .command("generic")
  .description("Generate PATH wrapper scripts for generic agents")
  .action(() => {
    const configPath = resolve("signet.yml");
    if (!existsSync(configPath)) {
      console.error("Error: signet.yml not found. Run 'signet init' first.");
      process.exit(1);
    }

    const config = parsePolicyFile(configPath);
    const binDir = join(SIGNET_DIR, "bin");
    const wrapped = generateWrappers(config.scope, binDir);

    if (wrapped.length === 0) {
      console.log("No shell rules to wrap.");
    } else {
      console.log(`Generated wrappers: ${wrapped.join(", ")}`);
      console.log(`\nAdd to your shell profile:\n  ${generatePathSetup(binDir)}`);
    }
  });

adaptCmd
  .command("cursor")
  .description("Generate Cursor settings from signet.yml")
  .option("--project-dir <dir>", "Project directory", process.cwd())
  .action((opts) => {
    const configPath = resolve("signet.yml");
    if (!existsSync(configPath)) {
      console.error("Error: signet.yml not found. Run 'signet init' first.");
      process.exit(1);
    }

    const config = parsePolicyFile(configPath);
    generateCursorSettings(config.scope, opts.projectDir);
    console.log("Cursor adapter configured:");
    console.log("  .cursor/rules/signet-policy.mdc — policy rules generated");
    console.log("  .cursorignore — blocked paths added");
  });

// ─── signet demo ───
program
  .command("demo")
  .description("Interactive walkthrough of signet's core concepts (no setup required)")
  .action(async () => {
    const { generateKeyPair: genKP, encodeBase64: enc, sign: signBytes } = await import("./crypto/keys");
    const { createDelegation: createDeleg, verifyDelegation: verifyDeleg } = await import("./crypto/delegation");
    const { signActionRequest, evaluate: evalReq, verifyDecision: verifyDec } = await import("./engine/evaluator");
    const { matchShellDetailed, matchFilesystemDetailed } = await import("./policy/matcher");

    const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
    const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
    const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
    const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
    const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
    const cyan = (s: string) => `\x1b[36m${s}\x1b[0m`;

    const wait = (ms: number) => new Promise(r => setTimeout(r, ms));
    const step = async (label: string) => {
      console.log();
      console.log(bold(`── ${label} ──`));
      await wait(500);
    };

    console.log();
    console.log(bold("signet demo"));
    console.log(dim("Simulated agent session — no setup required"));
    console.log(dim("─────────────────────────────────────────────"));

    // Step 1: Key Generation
    await step("Step 1: Key Generation");
    const userKey = genKP();
    const agentKey = genKP();
    console.log(`  User  keypair: ${cyan(enc(userKey.publicKey).substring(0, 32))}...`);
    console.log(`  Agent keypair: ${cyan(enc(agentKey.publicKey).substring(0, 32))}...`);
    console.log(dim("  Both are Ed25519 keypairs (tweetnacl). Private keys never leave the machine."));

    // Step 2: Policy
    await step("Step 2: Policy (signet.yml)");
    const scope: import("./policy/scope").Scope = {
      filesystem: {
        writable: ["./src/**", "./test/**"],
        readable: ["./**"],
        blocked: ["./.env", "~/.ssh/**", "~/.aws/**"],
      },
      network: {
        allow: ["github.com", "registry.npmjs.org"],
        deny: ["*"],
      },
      shell: {
        deny: ["rm -rf *", "sudo *"],
        ask: ["git push *", "npm publish *"],
        allow: ["npm test", "npm run *"],
      },
    };
    console.log(`  filesystem: ${green("writable")} ./src/** ./test/**  ${red("blocked")} .env ~/.ssh/**`);
    console.log(`  network:    ${green("allow")} github.com npmjs.org  ${red("deny")} *`);
    console.log(`  shell:      ${green("allow")} npm test  ${yellow("ask")} git push  ${red("deny")} rm -rf, sudo`);

    // Step 3: Delegation Token
    await step("Step 3: Delegation Token");
    const agentPub = enc(agentKey.publicKey);
    const token = createDeleg(userKey, agentPub, scope, {
      expires_at: new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString(),
      max_uses: 50,
    });
    const verified = verifyDeleg(token, enc(userKey.publicKey));
    console.log(`  Issuer:  ${dim(token.issuer.substring(0, 24) + "...")}`);
    console.log(`  Subject: ${dim(token.subject.substring(0, 24) + "...")}`);
    console.log(`  Expires: ${token.expires_at}`);
    console.log(`  Max uses: ${token.max_uses}`);
    console.log(`  Signature verified: ${verified ? green("true") : red("false")}`);
    console.log(dim("  User signs the scope + constraints. Agent cannot modify the token."));

    // Step 4: Simulated Requests
    await step("Step 4: Agent Requests → Policy Evaluation");
    console.log();

    const scenarios: Array<{
      action: string;
      target: string;
      desc: string;
    }> = [
      { action: "fs_write", target: "./src/index.ts", desc: "Agent writes to source file" },
      { action: "fs_read", target: "./.env", desc: "Agent tries to read .env" },
      { action: "shell", target: "npm test", desc: "Agent runs npm test" },
      { action: "shell", target: "git push origin main", desc: "Agent tries git push" },
      { action: "shell", target: "rm -rf /", desc: "Agent tries rm -rf" },
      { action: "net_connect", target: "github.com", desc: "Agent connects to GitHub" },
      { action: "net_connect", target: "evil.com", desc: "Agent connects to unknown host" },
    ];

    const auditEntries: Array<{ icon: string; action: string; target: string; result: string }> = [];

    for (const s of scenarios) {
      const req = signActionRequest(
        {
          agent_id: agentPub,
          action: s.action,
          target: s.target,
          timestamp: new Date().toISOString(),
        },
        agentKey.secretKey,
      );

      const decision = await evalReq(req, token, scope, userKey, {
        onAsk: async () => {
          // デモでは自動承認
          return true;
        },
      });

      let icon: string;
      let resultLabel: string;
      if (decision.allowed) {
        if (decision.decided_by === "user") {
          icon = yellow("?→✓");
          resultLabel = yellow("ask → approved");
        } else {
          icon = green("✓");
          resultLabel = green("allow");
        }
      } else {
        icon = red("✗");
        resultLabel = red("deny");
      }

      console.log(`  ${icon}  ${s.desc}`);
      console.log(dim(`     ${s.action}: "${s.target}" → ${decision.allowed ? "allowed" : "denied"} (${decision.decided_by})`));
      console.log(dim(`     decision signed: ${decision.signature.substring(0, 24)}...`));

      auditEntries.push({
        icon: decision.allowed ? (decision.decided_by === "user" ? "?" : "✓") : "✗",
        action: s.action,
        target: s.target,
        result: decision.allowed ? "allowed" : "denied",
      });

      await wait(300);
    }

    // Step 5: Audit Trail
    await step("Step 5: Audit Trail");
    console.log(dim("  Every request and decision is logged with chain hashing (SHA-256)."));
    console.log(dim("  Each entry's hash includes the previous hash → tamper-evident chain."));
    console.log();
    let prevHash = "0".repeat(64);
    for (let i = 0; i < auditEntries.length; i++) {
      const e = auditEntries[i];
      const hash = createHash("sha256")
        .update(prevHash + e.action + e.target + e.result)
        .digest("hex");
      const icon = e.result === "allowed" ? green("✓") : red("✗");
      console.log(`  ${icon} ${e.action.padEnd(14)} ${e.target.padEnd(25)} → ${e.result}`);
      console.log(dim(`    chain: ${hash.substring(0, 48)}...`));
      prevHash = hash;
    }
    console.log();
    console.log(dim("  If any entry is modified, the chain breaks. `signet log --verify` detects it."));

    // Summary
    await step("Summary");
    console.log(`  ${green("✓")} Ed25519 keypairs generated for user and agent`);
    console.log(`  ${green("✓")} Delegation token scopes what the agent can do`);
    console.log(`  ${green("✓")} Every request is signed by the agent`);
    console.log(`  ${green("✓")} Every decision is signed by the user's key`);
    console.log(`  ${green("✓")} Chain-hashed audit trail is tamper-evident`);
    console.log(`  ${green("✓")} Credential vault isolates .env files (AES-256-CBC)`);
    console.log();
    console.log(bold("  Get started:"));
    console.log(`    ${cyan("npm install -g signet")}`);
    console.log(`    ${cyan("signet init --template node")}`);
    console.log(`    ${cyan("signet activate")}`);
    console.log();
    console.log(dim("  https://github.com/anthropics/signet"));
    console.log();
  });

// ─── Parse and run ───
const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith("/index.ts") ||
    process.argv[1].endsWith("/index.js") ||
    process.argv[1].endsWith("/signet"));

if (isDirectRun) {
  program.parse();
}

export function parseDuration(str: string): number | null {
  const match = str.match(/^(\d+)(m|h|d)$/);
  if (!match) return null;
  const value = parseInt(match[1]);
  const unit = match[2];
  switch (unit) {
    case "m": return value * 60 * 1000;
    case "h": return value * 60 * 60 * 1000;
    case "d": return value * 24 * 60 * 60 * 1000;
    default: return null;
  }
}

export interface DetectResult {
  type: string;
  yml: string;
  notes: string[];
}

export function detectProject(dir: string): DetectResult {
  const notes: string[] = [];
  const has = (f: string) => existsSync(join(dir, f));

  // プロジェクトタイプ検出
  const isNode = has("package.json");
  const isPython = has("pyproject.toml") || has("requirements.txt") || has("setup.py");
  const type = isNode ? "node" : isPython ? "python" : "general";

  // writable ディレクトリ検出
  const writableDirs: string[] = [];
  const commonSrcDirs = ["src", "lib", "app", "components", "pages", "routes", "api"];
  const commonTestDirs = ["test", "tests", "__tests__", "spec"];
  for (const d of commonSrcDirs) {
    if (has(d)) writableDirs.push(`./${d}/**`);
  }
  for (const d of commonTestDirs) {
    if (has(d)) writableDirs.push(`./${d}/**`);
  }
  if (has("docs")) writableDirs.push("./docs/**");
  if (writableDirs.length === 0) {
    writableDirs.push("./src/**", "./test/**");
  }

  // writable設定ファイル
  if (isNode) {
    writableDirs.push("./package.json", "./tsconfig.json");
  }
  if (isPython) {
    if (has("pyproject.toml")) writableDirs.push("./pyproject.toml");
    if (has("requirements.txt")) writableDirs.push("./requirements.txt");
  }

  // blocked ファイル検出
  const blockedFiles = ["./.env", "./.env.*", "~/.ssh/**", "~/.aws/**"];
  if (isNode && has(".npmrc")) {
    blockedFiles.push("./.npmrc");
    notes.push("Found .npmrc — added to blocked list");
  }
  if (isPython && has(".pypirc")) {
    blockedFiles.push("./.pypirc");
  }

  // .env ファイル検出
  const envFiles: string[] = [];
  try {
    for (const f of readdirSync(dir) as string[]) {
      if (f.startsWith(".env") && f !== ".env.example" && f !== ".env.sample" && f !== ".env.template") {
        if (has(f)) envFiles.push(f);
      }
    }
  } catch { /* ignore */ }
  if (envFiles.length > 0) {
    notes.push(`Found ${envFiles.length} .env file(s) — will be protected by vault`);
  }

  // network 許可リスト
  const networkAllow: string[] = ["github.com"];
  if (isNode) {
    networkAllow.push("registry.npmjs.org", "registry.yarnpkg.com");
  }
  if (isPython) {
    networkAllow.push("pypi.org", "files.pythonhosted.org");
  }

  // git remote から追加ドメイン検出
  try {
    const gitConfig = readFileSync(join(dir, ".git", "config"), "utf-8");
    const urlMatch = gitConfig.match(/url\s*=\s*(?:https?:\/\/|git@)([^/:]+)/);
    if (urlMatch) {
      const host = urlMatch[1];
      if (!networkAllow.includes(host) && host !== "github.com") {
        networkAllow.push(host);
        notes.push(`Found git remote: ${host} — added to network allow`);
      }
    }
  } catch { /* no git or no remote */ }

  // shell ルール
  const shellAllow: string[] = [];
  const shellDeny = [
    "rm -rf *", "sudo *", "chmod 777 *",
    "curl *", "wget *", "nc *", "scp *", "rsync *",
    "env", "printenv *",
  ];
  const shellAsk = ["git push *"];

  if (isNode) {
    shellAllow.push("npm test *", "npm run *", "npx *", "node *", "tsc *");
    shellAsk.push("npm publish *");
  }
  if (isPython) {
    shellAllow.push("python *", "pytest *", "pip install *", "poetry *", "ruff *", "mypy *");
    shellAsk.push("twine upload *", "poetry publish *");
  }
  if (!isNode && !isPython) {
    shellAllow.push("make *", "git status", "git diff *", "git log *");
  }

  // credential ルール
  let credentialSection = "";
  if (isNode) {
    credentialSection = `
  credentials:
    github_token:
      source: "env:GITHUB_TOKEN"
      allowed_actions:
        - "git push *"
        - "gh pr create *"
      max_uses: 20
      require_approval: false
    npm_token:
      source: "env:NPM_TOKEN"
      allowed_actions:
        - "npm publish *"
      max_uses: 3
      require_approval: true
`;
  } else if (isPython) {
    credentialSection = `
  credentials:
    github_token:
      source: "env:GITHUB_TOKEN"
      allowed_actions:
        - "git push *"
        - "gh pr create *"
      max_uses: 20
      require_approval: false
    pypi_token:
      source: "env:PYPI_TOKEN"
      allowed_actions:
        - "twine upload *"
        - "poetry publish *"
      max_uses: 3
      require_approval: true
`;
  }

  notes.push(`Detected: ${type} project`);
  notes.push(`Writable dirs: ${writableDirs.filter(d => !d.includes(".")).length} found`);
  notes.push(`Network allow: ${networkAllow.join(", ")}`);

  // YAML生成
  const yml = `version: 1
defaults:
  expires: "4h"

scope:
  filesystem:
    writable:
${writableDirs.map(d => `      - "${d}"`).join("\n")}
    readable:
      - "./**"
    blocked:
${blockedFiles.map(f => `      - "${f}"`).join("\n")}

  network:
    allow:
${networkAllow.map(h => `      - "${h}"`).join("\n")}
    deny:
      - "*"
${credentialSection}
  shell:
    allow:
${shellAllow.map(c => `      - "${c}"`).join("\n")}
    deny:
${shellDeny.map(c => `      - "${c}"`).join("\n")}
    ask:
${shellAsk.map(c => `      - "${c}"`).join("\n")}
`;

  return { type, yml, notes };
}

export function generateDefaultConfig(): string {
  return `version: 1
defaults:
  expires: "4h"

scope:
  filesystem:
    writable:
      - "./src/**"
      - "./test/**"
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
    deny:
      - "*"

  shell:
    deny:
      - "rm -rf *"
      - "sudo *"
    ask:
      - "git push *"
      - "npm publish *"
`;
}
