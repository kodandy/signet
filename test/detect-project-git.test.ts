import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { detectProject } from "../src/index";

const TEST_DIR = join(tmpdir(), `signet-detect-git-${Date.now()}`);

beforeEach(() => {
  mkdirSync(TEST_DIR, { recursive: true });
});

afterEach(() => {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true, force: true });
  }
});

describe("detectProject git remote detection", () => {
  test("extracts HTTPS remote host from .git/config", () => {
    mkdirSync(join(TEST_DIR, ".git"), { recursive: true });
    writeFileSync(
      join(TEST_DIR, ".git", "config"),
      `[core]
	repositoryformatversion = 0
[remote "origin"]
	url = https://gitlab.example.com/team/repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
`,
    );

    const result = detectProject(TEST_DIR);
    expect(result.yml).toContain("gitlab.example.com");
    expect(result.notes.find((n) => n.includes("gitlab.example.com"))).toBeDefined();
  });

  test("extracts SSH remote host from .git/config", () => {
    mkdirSync(join(TEST_DIR, ".git"), { recursive: true });
    writeFileSync(
      join(TEST_DIR, ".git", "config"),
      `[remote "origin"]
	url = git@bitbucket.org:team/repo.git
`,
    );

    const result = detectProject(TEST_DIR);
    expect(result.yml).toContain("bitbucket.org");
    expect(result.notes.find((n) => n.includes("bitbucket.org"))).toBeDefined();
  });

  test("does not duplicate github.com if remote is github.com", () => {
    mkdirSync(join(TEST_DIR, ".git"), { recursive: true });
    writeFileSync(
      join(TEST_DIR, ".git", "config"),
      `[remote "origin"]
	url = https://github.com/user/repo.git
`,
    );

    const result = detectProject(TEST_DIR);
    // github.com should appear exactly once in network allow
    const matches = result.yml.match(/github\.com/g);
    expect(matches?.length).toBe(1);
  });

  test("no error when .git/config does not exist", () => {
    // No .git directory at all
    const result = detectProject(TEST_DIR);
    expect(result.type).toBe("general");
    // Should still have github.com as default
    expect(result.yml).toContain("github.com");
  });

  test("no error when .git/config has no remote", () => {
    mkdirSync(join(TEST_DIR, ".git"), { recursive: true });
    writeFileSync(
      join(TEST_DIR, ".git", "config"),
      `[core]
	repositoryformatversion = 0
	filemode = true
`,
    );

    const result = detectProject(TEST_DIR);
    expect(result.type).toBe("general");
    // No extra hosts beyond github.com
    const networkSection = result.yml.split("network:")[1]?.split("shell:")[0] ?? "";
    expect(networkSection).not.toContain("bitbucket");
    expect(networkSection).not.toContain("gitlab");
  });

  test("adds custom host note for non-github remote", () => {
    mkdirSync(join(TEST_DIR, ".git"), { recursive: true });
    writeFileSync(
      join(TEST_DIR, ".git", "config"),
      `[remote "origin"]
	url = https://gitea.internal.dev/org/project.git
`,
    );

    const result = detectProject(TEST_DIR);
    const note = result.notes.find((n) => n.includes("gitea.internal.dev"));
    expect(note).toBeDefined();
    expect(note).toContain("added to network allow");
  });
});
