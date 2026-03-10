#!/usr/bin/env node
import { Command } from "commander";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";

import { generateKeyPair, saveKeyPair, loadKeyPair, encodeBase64, decodeBase64 } from "./crypto/keys";
import { createDelegation } from "./crypto/delegation";
import { parsePolicyFile } from "./policy/parser";
import { matchShell, matchFilesystem, matchNetwork, matchCredential, type MatchResult } from "./policy/matcher";
import { AuditLogger } from "./audit/logger";
import { activate, deactivate, getVaultState } from "./vault/manager";
import { generateClaudeCodeSettings } from "./adapters/claude-code";
import { generateWrappers, generatePathSetup } from "./adapters/generic";

const SIGNET_DIR = join(homedir(), ".signet");

const program = new Command();

program
  .name("signet")
  .description("Cryptographic authorization delegation layer for local AI agents")
  .version("0.1.0");

// ─── signet init ───
program
  .command("init")
  .description("Initialize signet: generate keys and create signet.yml (Example: signet init --template node --claude-code)")
  .option("--template <name>", "Use a preset template (node, python, general)", "general")
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
    } else {
      const templatePath = join(__dirname, "..", "templates", `${opts.template}.yml`);
      if (existsSync(templatePath)) {
        const template = readFileSync(templatePath, "utf-8");
        writeFileSync(configPath, template);
        console.log(`Created signet.yml (template: ${opts.template})`);
      } else {
        // テンプレートが見つからない場合はデフォルト生成
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

      const state = activate({ projectDir: process.cwd() });
      console.log("Vault activated");
      if (state.evacuatedFiles.length > 0) {
        console.log("  Evacuated files:", state.evacuatedFiles.join(", "));
      }
      if (state.evacuatedVars.length > 0) {
        console.log("  Evacuated env vars:", state.evacuatedVars.join(", "));
      }
    } catch (err: unknown) {
      console.error("Error:", err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

// ─── signet deactivate ───
program
  .command("deactivate")
  .description("Deactivate vault and restore credentials")
  .action(() => {
    try {
      const state = deactivate();
      console.log("Vault deactivated");
      if (state.evacuatedFiles.length > 0) {
        console.log("  Restored files:", state.evacuatedFiles.join(", "));
      }
    } catch (err: unknown) {
      console.error("Error:", err instanceof Error ? err.message : String(err));
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

    let result: MatchResult;
    let label: string;

    switch (type) {
      case "shell":
        result = matchShell(scope.shell, target);
        label = `shell: "${target}"`;
        break;
      case "fs_read":
        result = matchFilesystem(scope.filesystem, target, "read");
        label = `fs_read: ${target}`;
        break;
      case "fs_write":
        result = matchFilesystem(scope.filesystem, target, "write");
        label = `fs_write: ${target}`;
        break;
      case "network":
        result = matchNetwork(scope.network, target);
        label = `network: ${target}`;
        break;
      case "credential":
        result = matchCredential(scope.credentials, target, opts.purpose);
        label = `credential: ${target}${opts.purpose ? ` (${opts.purpose})` : ""}`;
        break;
      default:
        console.error(`Error: Unknown type "${type}". Use: shell, fs_read, fs_write, network, credential`);
        process.exit(1);
    }

    const icon = result === "allow" ? "\u2705" : result === "deny" ? "\u274C" : result === "ask" ? "\u2753" : "\u2796";
    console.log(`${icon} ${label} → ${result}`);
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

// ─── Parse and run ───
program.parse();

function parseDuration(str: string): number | null {
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

function generateDefaultConfig(): string {
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
