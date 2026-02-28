#!/usr/bin/env node
import { Command } from "commander";
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";

import { generateKeyPair, saveKeyPair, loadKeyPair, encodeBase64 } from "./crypto/keys";
import { createDelegation } from "./crypto/delegation";
import { parsePolicyFile } from "./policy/parser";
import { matchShell, matchFilesystem, matchNetwork, matchCredential } from "./policy/matcher";
import { AuditLogger } from "./audit/logger";
import { activate, deactivate, getVaultState } from "./vault/manager";

const SIGNET_DIR = join(homedir(), ".signet");

const program = new Command();

program
  .name("signet")
  .description("Cryptographic authorization delegation layer for local AI agents")
  .version("0.1.0");

// ─── signet init ───
program
  .command("init")
  .description("Initialize signet: generate keys and create signet.yml")
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
      console.log("Claude Code adapter setup: run 'signet adapt claude-code'");
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
  .description("Show current signet status")
  .action(() => {
    const userKeyPath = join(SIGNET_DIR, "user.key");
    const configPath = resolve("signet.yml");
    const vaultState = getVaultState();

    console.log("signet status:");
    console.log("  User key:", existsSync(userKeyPath) ? "configured" : "not found");
    console.log("  Policy:", existsSync(configPath) ? "signet.yml found" : "not found");
    console.log("  Vault:", vaultState?.active ? "active" : "inactive");

    if (existsSync(userKeyPath)) {
      const kp = loadKeyPair(userKeyPath);
      console.log("  Public key:", encodeBase64(kp.publicKey));
    }
  });

// ─── signet log ───
program
  .command("log")
  .description("View audit log")
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
  .command("check <command>")
  .description("Dry-run policy check for a command")
  .action((command: string) => {
    const configPath = resolve("signet.yml");
    if (!existsSync(configPath)) {
      console.error("Error: signet.yml not found.");
      process.exit(1);
    }

    const config = parsePolicyFile(configPath);
    const scope = config.scope;

    const shellResult = matchShell(scope.shell, command);
    const icon = shellResult === "allow" ? "\u2705" : shellResult === "deny" ? "\u274C" : shellResult === "ask" ? "\u2753" : "\u2796";

    console.log(`${icon} shell: "${command}" → ${shellResult}`);
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

// ─── Parse and run ───
program.parse();

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
