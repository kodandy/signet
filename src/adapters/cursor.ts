import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Scope } from "../policy/scope";

/**
 * Cursor adapter
 * signet adapt cursor 時に:
 *   1. .cursor/rules にセキュリティポリシールールファイルを生成
 *   2. .cursorignore にブロック対象パスを追加
 */
export function generateCursorSettings(scope: Scope, projectDir: string): void {
  // 1. .cursor/rules/signet-policy.mdc にポリシー注入
  const cursorRulesDir = join(projectDir, ".cursor", "rules");
  if (!existsSync(cursorRulesDir)) {
    mkdirSync(cursorRulesDir, { recursive: true });
  }

  const rulesPath = join(cursorRulesDir, "signet-policy.mdc");
  const rulesContent = generateCursorRules(scope);
  writeFileSync(rulesPath, rulesContent);

  // 2. .cursorignore にブロック対象を追加
  const ignorePath = join(projectDir, ".cursorignore");
  const ignoreContent = generateCursorIgnore(scope);

  if (existsSync(ignorePath)) {
    const existing = readFileSync(ignorePath, "utf-8");
    if (!existing.includes("# signet:begin")) {
      writeFileSync(ignorePath, existing.trimEnd() + "\n\n" + ignoreContent);
    } else {
      // 既存のsignetセクションを更新
      const updated = existing.replace(
        /# signet:begin[\s\S]*# signet:end/,
        ignoreContent.trim(),
      );
      writeFileSync(ignorePath, updated);
    }
  } else {
    writeFileSync(ignorePath, ignoreContent);
  }
}

function generateCursorRules(scope: Scope): string {
  const lines: string[] = [
    "---",
    "description: Security policy enforced by signet",
    "globs: \"**/*\"",
    "alwaysApply: true",
    "---",
    "",
    "# Signet Security Policy",
    "",
    "This project is protected by signet. You MUST follow these rules:",
    "",
  ];

  if (scope.filesystem?.blocked?.length) {
    lines.push("## Blocked Paths (NEVER read or write)");
    for (const p of scope.filesystem.blocked) {
      lines.push(`- \`${p}\``);
    }
    lines.push("");
  }

  if (scope.filesystem?.writable?.length) {
    lines.push("## Writable Paths (allowed to modify)");
    for (const p of scope.filesystem.writable) {
      lines.push(`- \`${p}\``);
    }
    lines.push("");
  }

  if (scope.network?.deny?.includes("*") && scope.network.allow?.length) {
    lines.push("## Network Allowlist");
    lines.push("Only the following domains are permitted:");
    for (const d of scope.network.allow) {
      lines.push(`- \`${d}\``);
    }
    lines.push("");
  }

  if (scope.shell?.deny?.length) {
    lines.push("## Denied Commands (NEVER execute)");
    for (const c of scope.shell.deny) {
      lines.push(`- \`${c}\``);
    }
    lines.push("");
  }

  if (scope.shell?.ask?.length) {
    lines.push("## Commands Requiring Confirmation");
    for (const c of scope.shell.ask) {
      lines.push(`- \`${c}\``);
    }
    lines.push("");
  }

  return lines.join("\n");
}

function generateCursorIgnore(scope: Scope): string {
  const lines: string[] = ["# signet:begin"];

  if (scope.filesystem?.blocked?.length) {
    for (const pattern of scope.filesystem.blocked) {
      // .cursorignore uses gitignore-style patterns
      // Convert signet patterns: remove leading ./ and ~ paths
      const normalized = pattern.replace(/^\.\//, "");
      // Skip home-relative paths (not relevant for project-level ignore)
      if (normalized.startsWith("~/")) continue;
      lines.push(normalized);
    }
  }

  lines.push("# signet:end");
  return lines.join("\n") + "\n";
}
