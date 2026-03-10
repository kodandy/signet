import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Scope } from "../policy/scope";

/**
 * Claude Code adapter
 * signet init --claude-code 時に:
 *   1. .claude/settings.json にdeny/askルール注入
 *   2. CLAUDE.md にセキュリティポリシー追記
 */
export function generateClaudeCodeSettings(scope: Scope, projectDir: string): void {
  const claudeDir = join(projectDir, ".claude");
  if (!existsSync(claudeDir)) {
    mkdirSync(claudeDir, { recursive: true });
  }

  // 1. settings.json
  const settingsPath = join(claudeDir, "settings.json");
  const existing = existsSync(settingsPath)
    ? JSON.parse(readFileSync(settingsPath, "utf-8"))
    : {};

  const generated = generatePermissions(scope);
  const existingPerms = existing.permissions ?? {};
  const settings = {
    ...existing,
    permissions: {
      ...existingPerms,
      deny: mergeUnique(existingPerms.deny, generated.deny),
      ask: mergeUnique(existingPerms.ask, generated.ask),
    },
    sandbox: generateSandboxConfig(scope, existing.sandbox),
  };

  writeFileSync(settingsPath, JSON.stringify(settings, null, 2));

  // 2. CLAUDE.mdにポリシー追記
  const claudeMdPath = join(projectDir, "CLAUDE.md");
  const section = generateClaudeMdSection(scope);

  if (existsSync(claudeMdPath)) {
    const content = readFileSync(claudeMdPath, "utf-8");
    if (!content.includes("<!-- signet:begin -->")) {
      writeFileSync(claudeMdPath, content + "\n" + section);
    } else {
      // 既存のsignetセクションを更新
      const updated = content.replace(
        /<!-- signet:begin -->[\s\S]*<!-- signet:end -->/,
        section.trim(),
      );
      writeFileSync(claudeMdPath, updated);
    }
  } else {
    writeFileSync(claudeMdPath, section);
  }
}

function mergeUnique(existing: string[] | undefined, added: string[]): string[] {
  const set = new Set(existing ?? []);
  for (const item of added) set.add(item);
  return [...set];
}

function generatePermissions(scope: Scope): Record<string, string[]> {
  const deny: string[] = [];
  const ask: string[] = [];

  // shell deny → Bash deny
  if (scope.shell?.deny) {
    for (const pattern of scope.shell.deny) {
      deny.push(`Bash(${pattern})`);
    }
  }

  // shell ask → Bash ask
  if (scope.shell?.ask) {
    for (const pattern of scope.shell.ask) {
      ask.push(`Bash(${pattern})`);
    }
  }

  // filesystem blocked → Read/Write/Edit deny
  if (scope.filesystem?.blocked) {
    for (const pattern of scope.filesystem.blocked) {
      deny.push(`Read(${pattern})`);
      deny.push(`Write(${pattern})`);
      deny.push(`Edit(${pattern})`);
    }
  }

  // network allow + deny:* → WebFetch deny for non-allowed domains
  if (scope.network?.deny?.includes("*") && scope.network.allow?.length) {
    // Deny all network tools except allowed domains
    deny.push("Bash(curl *)");
    deny.push("Bash(wget *)");
  }

  return { deny, ask };
}

function generateSandboxConfig(scope: Scope, existing?: Record<string, unknown>): Record<string, unknown> {
  const sandbox: Record<string, unknown> = {
    ...existing,
    enabled: true,
  };

  // filesystem → sandbox.filesystem
  const fs: Record<string, string[]> = {};
  if (scope.filesystem?.writable) {
    fs.allowWrite = [...(scope.filesystem.writable)];
  }
  if (scope.filesystem?.blocked) {
    const denyWrite: string[] = [];
    const denyRead: string[] = [];
    for (const pattern of scope.filesystem.blocked) {
      denyWrite.push(pattern);
      denyRead.push(pattern);
    }
    // ホームディレクトリの機密パスも追加
    denyRead.push("~/.aws/**");
    denyRead.push("~/.ssh/**");
    denyRead.push("~/.gnupg/**");
    fs.denyWrite = [...new Set(denyWrite)];
    fs.denyRead = [...new Set(denyRead)];
  }
  if (Object.keys(fs).length > 0) {
    sandbox.filesystem = fs;
  }

  // network → sandbox.network
  if (scope.network) {
    const network: Record<string, unknown> = {};
    // deny: ["*"] + allow list → allowedDomains
    if (scope.network.deny?.includes("*") && scope.network.allow?.length) {
      network.allowedDomains = [...scope.network.allow];
    }
    if (Object.keys(network).length > 0) {
      sandbox.network = network;
    }
  }

  return sandbox;
}

function generateClaudeMdSection(scope: Scope): string {
  const lines: string[] = [
    "<!-- signet:begin -->",
    "## Security Policy (managed by signet)",
    "",
    "This project is protected by [signet](https://github.com/kodandy/signet).",
    "",
  ];

  if (scope.filesystem?.blocked?.length) {
    lines.push("### Blocked paths (never access)");
    for (const p of scope.filesystem.blocked) {
      lines.push(`- \`${p}\``);
    }
    lines.push("");
  }

  if (scope.network?.deny?.includes("*") && scope.network.allow?.length) {
    lines.push("### Network (allowlist only)");
    for (const d of scope.network.allow) {
      lines.push(`- \`${d}\``);
    }
    lines.push("");
  }

  if (scope.shell?.deny?.length) {
    lines.push("### Denied commands");
    for (const c of scope.shell.deny) {
      lines.push(`- \`${c}\``);
    }
    lines.push("");
  }

  lines.push("<!-- signet:end -->");
  return lines.join("\n") + "\n";
}
