import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";

const TEST_DIR = join(tmpdir(), `signet-detect-test-${Date.now()}`);
const SIGNET_HOME = join(TEST_DIR, ".signet");

function runSignet(args: string, opts?: { cwd?: string }): { stdout: string; stderr: string; exitCode: number } {
  const cwd = opts?.cwd ?? TEST_DIR;
  try {
    const result = execSync(
      `npx tsx ${join(process.cwd(), "src/index.ts")} ${args}`,
      {
        cwd,
        env: { ...process.env, HOME: TEST_DIR, SIGNET_DIR: SIGNET_HOME },
        encoding: "utf-8",
        timeout: 15000,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    return { stdout: result, stderr: "", exitCode: 0 };
  } catch (err: any) {
    return {
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
      exitCode: err.status ?? 1,
    };
  }
}

beforeEach(() => {
  mkdirSync(TEST_DIR, { recursive: true });
});

afterEach(() => {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true, force: true });
  }
});

// ─── detectProject via `signet init --smart` ───

describe("signet init --smart", () => {
  test("detects Node.js project", () => {
    writeFileSync(join(TEST_DIR, "package.json"), '{"name":"test"}');
    mkdirSync(join(TEST_DIR, "src"), { recursive: true });
    mkdirSync(join(TEST_DIR, "test"), { recursive: true });

    const { stdout, exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);
    expect(stdout).toContain("auto-detected: node");

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("./src/**");
    expect(yml).toContain("./test/**");
    expect(yml).toContain("./package.json");
    expect(yml).toContain("./tsconfig.json");
    expect(yml).toContain("registry.npmjs.org");
    expect(yml).toContain("npm test *");
    expect(yml).toContain("npm run *");
    expect(yml).toContain("npm publish *");
  });

  test("detects Python project (pyproject.toml)", () => {
    writeFileSync(join(TEST_DIR, "pyproject.toml"), "[project]\nname = 'test'\n");
    mkdirSync(join(TEST_DIR, "src"), { recursive: true });
    mkdirSync(join(TEST_DIR, "tests"), { recursive: true });

    const { stdout, exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);
    expect(stdout).toContain("auto-detected: python");

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("./src/**");
    expect(yml).toContain("./tests/**");
    expect(yml).toContain("./pyproject.toml");
    expect(yml).toContain("pypi.org");
    expect(yml).toContain("pytest *");
    expect(yml).toContain("twine upload *");
  });

  test("detects Python project (requirements.txt)", () => {
    writeFileSync(join(TEST_DIR, "requirements.txt"), "flask\n");

    const { stdout, exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);
    expect(stdout).toContain("auto-detected: python");

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("./requirements.txt");
    expect(yml).toContain("pip install *");
  });

  test("falls back to general for unknown project", () => {
    // Empty directory — no package.json, no pyproject.toml
    const { stdout, exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);
    expect(stdout).toContain("auto-detected: general");

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    // general projects get make and git commands
    expect(yml).toContain("make *");
    expect(yml).toContain("git status");
    // default writable dirs when none detected
    expect(yml).toContain("./src/**");
    expect(yml).toContain("./test/**");
  });

  test("detects .npmrc and adds to blocked list", () => {
    writeFileSync(join(TEST_DIR, "package.json"), '{"name":"test"}');
    writeFileSync(join(TEST_DIR, ".npmrc"), "//registry.npmjs.org/:_authToken=secret\n");

    const { stdout, exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);
    expect(stdout).toContain(".npmrc");

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("./.npmrc");
  });

  test("detects .env files and reports them", () => {
    writeFileSync(join(TEST_DIR, "package.json"), '{"name":"test"}');
    writeFileSync(join(TEST_DIR, ".env"), "SECRET=123\n");
    writeFileSync(join(TEST_DIR, ".env.local"), "LOCAL=abc\n");
    // .env.example should NOT be counted
    writeFileSync(join(TEST_DIR, ".env.example"), "EXAMPLE=placeholder\n");

    const { stdout, exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);
    expect(stdout).toContain(".env file(s)");
    expect(stdout).toContain("vault");
  });

  test("always blocks .env and ssh/aws", () => {
    const { exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("./.env");
    expect(yml).toContain("~/.ssh/**");
    expect(yml).toContain("~/.aws/**");
  });

  test("common deny rules are always present", () => {
    writeFileSync(join(TEST_DIR, "package.json"), '{"name":"test"}');

    const { exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("rm -rf *");
    expect(yml).toContain("sudo *");
    expect(yml).toContain("chmod 777 *");
    expect(yml).toContain("curl *");
    expect(yml).toContain("wget *");
  });

  test("detects multiple source directories", () => {
    writeFileSync(join(TEST_DIR, "package.json"), '{"name":"test"}');
    mkdirSync(join(TEST_DIR, "src"), { recursive: true });
    mkdirSync(join(TEST_DIR, "components"), { recursive: true });
    mkdirSync(join(TEST_DIR, "pages"), { recursive: true });
    mkdirSync(join(TEST_DIR, "docs"), { recursive: true });

    const { exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("./src/**");
    expect(yml).toContain("./components/**");
    expect(yml).toContain("./pages/**");
    expect(yml).toContain("./docs/**");
  });

  test("Node project includes credential section", () => {
    writeFileSync(join(TEST_DIR, "package.json"), '{"name":"test"}');

    const { exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("github_token");
    expect(yml).toContain("npm_token");
    expect(yml).toContain("env:GITHUB_TOKEN");
    expect(yml).toContain("env:NPM_TOKEN");
  });

  test("Python project includes pypi credential section", () => {
    writeFileSync(join(TEST_DIR, "pyproject.toml"), "[project]\nname = 'test'\n");

    const { exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("github_token");
    expect(yml).toContain("pypi_token");
    expect(yml).toContain("env:PYPI_TOKEN");
  });

  test("does not overwrite existing signet.yml", () => {
    writeFileSync(join(TEST_DIR, "signet.yml"), "existing: true\n");

    const { stdout, exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);
    expect(stdout).toContain("already exists");

    // File should be unchanged
    const content = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(content).toBe("existing: true\n");
  });

  test("git push is always in ask list", () => {
    writeFileSync(join(TEST_DIR, "package.json"), '{"name":"test"}');

    const { exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("git push *");
  });

  test("network defaults include github.com and deny *", () => {
    const { exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("github.com");
    expect(yml).toMatch(/deny:\s*\n\s*- "\*"/);
  });

  test("generated YAML has version 1 and 4h expiry", () => {
    const { exitCode } = runSignet("init --smart");
    expect(exitCode).toBe(0);

    const yml = readFileSync(join(TEST_DIR, "signet.yml"), "utf-8");
    expect(yml).toContain("version: 1");
    expect(yml).toContain('expires: "4h"');
  });
});
