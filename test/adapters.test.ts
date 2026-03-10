import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, readFileSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Scope } from "../src/policy/scope";
import { generateClaudeCodeSettings } from "../src/adapters/claude-code";
import { generateWrappers, generatePathSetup } from "../src/adapters/generic";

const testScope: Scope = {
  filesystem: {
    writable: ["./src/**"],
    readable: ["./**"],
    blocked: ["./.env", "~/.ssh/**"],
  },
  network: {
    allow: ["github.com", "registry.npmjs.org"],
    deny: ["*"],
  },
  shell: {
    deny: ["rm -rf *", "sudo *"],
    ask: ["git push *"],
  },
};

describe("adapters/claude-code", () => {
  const testDir = join(tmpdir(), `signet-adapter-test-${Date.now()}`);

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  test("generates .claude/settings.json with permissions", () => {
    generateClaudeCodeSettings(testScope, testDir);

    const settingsPath = join(testDir, ".claude", "settings.json");
    expect(existsSync(settingsPath)).toBe(true);

    const settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
    expect(settings.permissions.deny).toContain("Bash(rm -rf *)");
    expect(settings.permissions.deny).toContain("Bash(sudo *)");
    expect(settings.permissions.deny).toContain("Write(./.env)");
    expect(settings.permissions.ask).toContain("Bash(git push *)");
  });

  test("generates CLAUDE.md with signet section", () => {
    generateClaudeCodeSettings(testScope, testDir);

    const claudeMdPath = join(testDir, "CLAUDE.md");
    expect(existsSync(claudeMdPath)).toBe(true);

    const content = readFileSync(claudeMdPath, "utf-8");
    expect(content).toContain("<!-- signet:begin -->");
    expect(content).toContain("<!-- signet:end -->");
    expect(content).toContain("Blocked paths");
    expect(content).toContain("`./.env`");
    expect(content).toContain("`github.com`");
  });

  test("appends to existing CLAUDE.md", () => {
    const claudeMdPath = join(testDir, "CLAUDE.md");
    writeFileSync(claudeMdPath, "# My Project\n\nExisting content.\n");

    generateClaudeCodeSettings(testScope, testDir);

    const content = readFileSync(claudeMdPath, "utf-8");
    expect(content).toContain("# My Project");
    expect(content).toContain("Existing content.");
    expect(content).toContain("<!-- signet:begin -->");
  });

  test("updates existing signet section in CLAUDE.md", () => {
    const claudeMdPath = join(testDir, "CLAUDE.md");
    writeFileSync(claudeMdPath, "# My Project\n\n<!-- signet:begin -->\nold content\n<!-- signet:end -->\n");

    generateClaudeCodeSettings(testScope, testDir);

    const content = readFileSync(claudeMdPath, "utf-8");
    expect(content).not.toContain("old content");
    expect(content).toContain("Blocked paths");
  });

  test("merges with existing permissions instead of overwriting", () => {
    const claudeDir = join(testDir, ".claude");
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(
      join(claudeDir, "settings.json"),
      JSON.stringify({
        permissions: {
          deny: ["Bash(curl *)", "Bash(wget *)"],
          ask: ["Bash(docker *)"],
          allow: ["Read(**)"],
        },
      }),
    );

    generateClaudeCodeSettings(testScope, testDir);

    const settings = JSON.parse(readFileSync(join(claudeDir, "settings.json"), "utf-8"));
    // existing deny rules preserved
    expect(settings.permissions.deny).toContain("Bash(curl *)");
    expect(settings.permissions.deny).toContain("Bash(wget *)");
    // new signet deny rules added
    expect(settings.permissions.deny).toContain("Bash(rm -rf *)");
    expect(settings.permissions.deny).toContain("Bash(sudo *)");
    // existing ask rules preserved
    expect(settings.permissions.ask).toContain("Bash(docker *)");
    // new signet ask rules added
    expect(settings.permissions.ask).toContain("Bash(git push *)");
    // non-deny/ask permissions preserved
    expect(settings.permissions.allow).toEqual(["Read(**)"]);
  });

  test("deduplicates when running adapter twice", () => {
    generateClaudeCodeSettings(testScope, testDir);
    generateClaudeCodeSettings(testScope, testDir);

    const settings = JSON.parse(
      readFileSync(join(testDir, ".claude", "settings.json"), "utf-8"),
    );
    const denyCount = settings.permissions.deny.filter(
      (r: string) => r === "Bash(rm -rf *)",
    ).length;
    expect(denyCount).toBe(1);
  });

  test("throws when existing settings.json contains malformed JSON", () => {
    const claudeDir = join(testDir, ".claude");
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(join(claudeDir, "settings.json"), "{ not valid json }}}");

    expect(() => generateClaudeCodeSettings(testScope, testDir)).toThrow();
  });
});

describe("adapters/generic", () => {
  const testBinDir = join(tmpdir(), `signet-bin-test-${Date.now()}`);

  afterEach(() => {
    if (existsSync(testBinDir)) {
      rmSync(testBinDir, { recursive: true, force: true });
    }
  });

  test("generates wrapper scripts for deny/ask commands", () => {
    const wrapped = generateWrappers(testScope, testBinDir);

    expect(wrapped).toContain("rm");
    expect(wrapped).toContain("sudo");
    expect(wrapped).toContain("git");
    expect(wrapped.length).toBe(3);

    // ラッパースクリプトが存在
    expect(existsSync(join(testBinDir, "rm"))).toBe(true);
    expect(existsSync(join(testBinDir, "sudo"))).toBe(true);
    expect(existsSync(join(testBinDir, "git"))).toBe(true);
  });

  test("wrapper script contains original command lookup", () => {
    generateWrappers(testScope, testBinDir);

    const script = readFileSync(join(testBinDir, "rm"), "utf-8");
    expect(script).toContain("#!/usr/bin/env bash");
    expect(script).toContain("signet wrapper for rm");
    expect(script).toContain("exec \"$ORIGINAL\"");
  });

  test("generatePathSetup returns correct export", () => {
    const setup = generatePathSetup("/home/user/.signet/bin");
    expect(setup).toBe('export PATH="/home/user/.signet/bin:$PATH"');
  });

  test("generateWrappers returns empty array for scope with no shell rules", () => {
    const emptyScope: Scope = { filesystem: { readable: ["./**"] } };
    const wrapped = generateWrappers(emptyScope, testBinDir);

    expect(wrapped).toEqual([]);
  });
});
