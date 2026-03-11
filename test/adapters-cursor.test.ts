import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, readFileSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Scope } from "../src/policy/scope";
import { generateCursorSettings } from "../src/adapters/cursor";

const testScope: Scope = {
  filesystem: {
    writable: ["./src/**"],
    readable: ["./**"],
    blocked: ["./.env", "./.env.*", "~/.ssh/**", "~/.aws/**"],
  },
  network: {
    allow: ["github.com", "registry.npmjs.org"],
    deny: ["*"],
  },
  shell: {
    deny: ["rm -rf *", "sudo *"],
    ask: ["git push *", "npm publish *"],
  },
};

describe("adapters/cursor", () => {
  const testDir = join(tmpdir(), `signet-cursor-test-${Date.now()}`);

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  test("generates .cursor/rules/signet-policy.mdc", () => {
    generateCursorSettings(testScope, testDir);

    const rulesPath = join(testDir, ".cursor", "rules", "signet-policy.mdc");
    expect(existsSync(rulesPath)).toBe(true);

    const content = readFileSync(rulesPath, "utf-8");
    expect(content).toContain("description: Security policy enforced by signet");
    expect(content).toContain("alwaysApply: true");
  });

  test("rules file contains blocked paths", () => {
    generateCursorSettings(testScope, testDir);

    const content = readFileSync(
      join(testDir, ".cursor", "rules", "signet-policy.mdc"),
      "utf-8",
    );
    expect(content).toContain("`./.env`");
    expect(content).toContain("`~/.ssh/**`");
  });

  test("rules file contains writable paths", () => {
    generateCursorSettings(testScope, testDir);

    const content = readFileSync(
      join(testDir, ".cursor", "rules", "signet-policy.mdc"),
      "utf-8",
    );
    expect(content).toContain("`./src/**`");
  });

  test("rules file contains network allowlist", () => {
    generateCursorSettings(testScope, testDir);

    const content = readFileSync(
      join(testDir, ".cursor", "rules", "signet-policy.mdc"),
      "utf-8",
    );
    expect(content).toContain("`github.com`");
    expect(content).toContain("`registry.npmjs.org`");
  });

  test("rules file contains denied commands", () => {
    generateCursorSettings(testScope, testDir);

    const content = readFileSync(
      join(testDir, ".cursor", "rules", "signet-policy.mdc"),
      "utf-8",
    );
    expect(content).toContain("`rm -rf *`");
    expect(content).toContain("`sudo *`");
  });

  test("rules file contains ask commands", () => {
    generateCursorSettings(testScope, testDir);

    const content = readFileSync(
      join(testDir, ".cursor", "rules", "signet-policy.mdc"),
      "utf-8",
    );
    expect(content).toContain("`git push *`");
    expect(content).toContain("`npm publish *`");
  });

  test("generates .cursorignore with blocked paths", () => {
    generateCursorSettings(testScope, testDir);

    const ignorePath = join(testDir, ".cursorignore");
    expect(existsSync(ignorePath)).toBe(true);

    const content = readFileSync(ignorePath, "utf-8");
    expect(content).toContain("# signet:begin");
    expect(content).toContain("# signet:end");
    expect(content).toContain(".env");
    expect(content).toContain(".env.*");
  });

  test(".cursorignore skips home-relative paths", () => {
    generateCursorSettings(testScope, testDir);

    const content = readFileSync(join(testDir, ".cursorignore"), "utf-8");
    // ~/paths should not be in .cursorignore (project-level only)
    expect(content).not.toContain("~/.ssh");
    expect(content).not.toContain("~/.aws");
  });

  test("appends to existing .cursorignore", () => {
    const ignorePath = join(testDir, ".cursorignore");
    writeFileSync(ignorePath, "node_modules\ndist\n");

    generateCursorSettings(testScope, testDir);

    const content = readFileSync(ignorePath, "utf-8");
    expect(content).toContain("node_modules");
    expect(content).toContain("dist");
    expect(content).toContain("# signet:begin");
  });

  test("updates existing signet section in .cursorignore", () => {
    const ignorePath = join(testDir, ".cursorignore");
    writeFileSync(ignorePath, "node_modules\n\n# signet:begin\nold-pattern\n# signet:end\n");

    generateCursorSettings(testScope, testDir);

    const content = readFileSync(ignorePath, "utf-8");
    expect(content).not.toContain("old-pattern");
    expect(content).toContain(".env");
  });

  test("running adapter twice does not duplicate .cursorignore section", () => {
    generateCursorSettings(testScope, testDir);
    generateCursorSettings(testScope, testDir);

    const content = readFileSync(join(testDir, ".cursorignore"), "utf-8");
    const beginCount = (content.match(/# signet:begin/g) ?? []).length;
    expect(beginCount).toBe(1);
  });

  test("overwrites rules file on second run", () => {
    generateCursorSettings(testScope, testDir);

    const minimalScope: Scope = {
      filesystem: { readable: ["./**"] },
    };
    generateCursorSettings(minimalScope, testDir);

    const content = readFileSync(
      join(testDir, ".cursor", "rules", "signet-policy.mdc"),
      "utf-8",
    );
    // Should not contain old scope's blocked paths
    expect(content).not.toContain("`./.env`");
  });

  test("no network section when no deny-all rule", () => {
    const scopeNoNetDeny: Scope = {
      filesystem: { writable: ["./src/**"], readable: ["./**"] },
      network: { allow: ["github.com"] },
    };
    generateCursorSettings(scopeNoNetDeny, testDir);

    const content = readFileSync(
      join(testDir, ".cursor", "rules", "signet-policy.mdc"),
      "utf-8",
    );
    expect(content).not.toContain("Network Allowlist");
  });
});
