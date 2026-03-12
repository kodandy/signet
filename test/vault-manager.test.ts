import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, writeFileSync, readFileSync, mkdirSync, rmSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  injectForCommand,
  activate,
  deactivate,
  retrieveCredential,
  getVaultState,
  type VaultPaths,
} from "../src/vault/manager";

// テスト用パスを tmpdir 内に隔離するヘルパー
function makeTestPaths(baseDir: string): VaultPaths {
  return {
    vaultDir: join(baseDir, "vault"),
    vaultKeyPath: join(baseDir, "vault.key"),
    statePath: join(baseDir, "vault-state.json"),
  };
}

describe("vault/manager", () => {
  describe("injectForCommand", () => {
    test("injects env var for command execution", () => {
      const result = injectForCommand(
        "TEST_SIGNET_CRED",
        "secret-value-123",
        "echo $TEST_SIGNET_CRED",
      );

      expect(result.exitCode).toBe(0);
      // stdout中の秘密値はサニタイズされる
      expect(result.stdout).toContain("[SIGNET:REDACTED]");
    });

    test("credential is not visible after command completes", () => {
      injectForCommand("TEST_SIGNET_TEMP", "temp-secret", "echo ok");

      expect(process.env.TEST_SIGNET_TEMP).toBeUndefined();
    });

    test("returns exit code on command failure", () => {
      const result = injectForCommand("X", "v", "false");

      expect(result.exitCode).not.toBe(0);
    });

    test("captures stdout from command with redaction", () => {
      const result = injectForCommand("MY_VAR", "hello", "echo $MY_VAR world");

      expect(result.exitCode).toBe(0);
      // "hello" は4文字なのでサニタイズ対象
      expect(result.stdout).toContain("[SIGNET:REDACTED]");
      expect(result.stdout).toContain("world");
    });

    test("does not leak credential to parent process env", () => {
      const originalEnv = { ...process.env };

      injectForCommand("SIGNET_SECRET_KEY", "super-secret", "echo test");

      expect(process.env.SIGNET_SECRET_KEY).toBeUndefined();
      // 元の環境変数が変わっていないことを確認
      expect(process.env.HOME).toBe(originalEnv.HOME);
    });

    test("handles special characters in credential values", () => {
      const specialValue = 'pa$$word"with`special';
      const result = injectForCommand(
        "SPECIAL_CRED",
        specialValue,
        "printenv SPECIAL_CRED",
      );

      expect(result.exitCode).toBe(0);
      // 特殊文字を含む秘密値もサニタイズされる
      expect(result.stdout).not.toContain(specialValue);
      expect(result.stdout).toContain("[SIGNET:REDACTED]");
    });

    test("captures stderr from failing command", () => {
      const result = injectForCommand("X", "v", "echo error-output >&2 && false");

      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("error-output");
    });

    test("redacts credential value from stdout", () => {
      const secret = "super-secret-token-xyz";
      const result = injectForCommand(
        "LEAK_TEST",
        secret,
        "echo super-secret-token-xyz",
      );

      expect(result.exitCode).toBe(0);
      expect(result.stdout).not.toContain(secret);
      expect(result.stdout).toContain("[SIGNET:REDACTED]");
    });

    test("redacts credential value from stderr", () => {
      const secret = "my-api-key-12345";
      const result = injectForCommand(
        "LEAK_TEST2",
        secret,
        "echo my-api-key-12345 >&2 && false",
      );

      expect(result.stderr).not.toContain(secret);
      expect(result.stderr).toContain("[SIGNET:REDACTED]");
    });

    test("redacts multiple occurrences of credential in output", () => {
      const secret = "repeated-secret";
      const result = injectForCommand(
        "MULTI_LEAK",
        secret,
        "echo repeated-secret-repeated-secret",
      );

      expect(result.stdout).not.toContain(secret);
      // 2箇所がマスクされる
      const count = (result.stdout.match(/\[SIGNET:REDACTED\]/g) || []).length;
      expect(count).toBe(2);
    });

    test("does not redact short secrets (< 4 chars) to avoid false positives", () => {
      const result = injectForCommand(
        "SHORT_SEC",
        "abc",
        "echo abc",
      );

      // 短い秘密はマスクしない（false positive防止）
      expect(result.stdout.trim()).toBe("abc");
    });
  });

  describe("activate", () => {
    const testDir = join(tmpdir(), `signet-vault-activate-${Date.now()}`);
    let paths: VaultPaths;
    let projectDir: string;

    beforeEach(() => {
      projectDir = join(testDir, "project");
      mkdirSync(projectDir, { recursive: true });
      paths = makeTestPaths(join(testDir, "signet"));
    });

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("evacuates .env file and removes original", () => {
      const envPath = join(projectDir, ".env");
      writeFileSync(envPath, "API_KEY=secret123\nDB_URL=postgres://localhost");

      const state = activate({ projectDir, paths });

      expect(state.active).toBe(true);
      expect(state.evacuatedFiles).toHaveLength(1);
      expect(state.evacuatedFiles[0]).toBe(envPath);
      // 元ファイルは削除される
      expect(existsSync(envPath)).toBe(false);
      // vault ディレクトリに暗号化ファイルが作成される
      expect(existsSync(paths.vaultDir)).toBe(true);
    });

    test("evacuates environment variables", () => {
      const uniqueVar = `SIGNET_TEST_VAR_${Date.now()}`;
      process.env[uniqueVar] = "test-secret-value";

      const state = activate({
        projectDir,
        credentialEnvVars: [uniqueVar],
        paths,
      });

      expect(state.evacuatedVars).toContain(uniqueVar);
      expect(process.env[uniqueVar]).toBeUndefined();
    });

    test("returns correct VaultState", () => {
      writeFileSync(join(projectDir, ".env"), "SECRET=abc");

      const state = activate({ projectDir, paths });

      expect(state.active).toBe(true);
      expect(state.projectDir).toBe(projectDir);
      expect(state.evacuatedFiles).toHaveLength(1);
      expect(state.evacuatedVars).toHaveLength(0);
    });

    test("skips non-existent .env files", () => {
      // .env ファイルを作成しない
      const state = activate({ projectDir, paths });

      expect(state.active).toBe(true);
      expect(state.evacuatedFiles).toHaveLength(0);
    });

    test("throws when already active", () => {
      const state = activate({ projectDir, paths });
      expect(state.active).toBe(true);

      expect(() => activate({ projectDir, paths })).toThrow(
        "Vault is already active",
      );
    });

    test("skips env vars that are not set", () => {
      const state = activate({
        projectDir,
        credentialEnvVars: ["NONEXISTENT_VAR_12345"],
        paths,
      });

      expect(state.evacuatedVars).toHaveLength(0);
    });
  });

  describe("deactivate", () => {
    const testDir = join(tmpdir(), `signet-vault-deactivate-${Date.now()}`);
    let paths: VaultPaths;
    let projectDir: string;

    beforeEach(() => {
      projectDir = join(testDir, "project");
      mkdirSync(projectDir, { recursive: true });
      paths = makeTestPaths(join(testDir, "signet"));
    });

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("restores .env file to original location", () => {
      const envPath = join(projectDir, ".env");
      const originalContent = "API_KEY=secret123\nDB_URL=postgres://localhost";
      writeFileSync(envPath, originalContent);

      activate({ projectDir, paths });
      expect(existsSync(envPath)).toBe(false);

      const state = deactivate(paths);
      expect(state.active).toBe(false);
      expect(existsSync(envPath)).toBe(true);
      expect(readFileSync(envPath, "utf-8")).toBe(originalContent);
    });

    test("restores environment variables", () => {
      const uniqueVar = `SIGNET_DEACT_TEST_${Date.now()}`;
      process.env[uniqueVar] = "restore-me";

      activate({ projectDir, credentialEnvVars: [uniqueVar], paths });
      expect(process.env[uniqueVar]).toBeUndefined();

      deactivate(paths);
      expect(process.env[uniqueVar]).toBe("restore-me");

      // クリーンアップ
      delete process.env[uniqueVar];
    });

    test("returns VaultState with active: false", () => {
      activate({ projectDir, paths });

      const state = deactivate(paths);

      expect(state.active).toBe(false);
      expect(state.projectDir).toBe(projectDir);
    });

    test("throws when vault is not active", () => {
      expect(() => deactivate(paths)).toThrow("Vault is not active");
    });

    test("force deactivate clears state even when vault is not active", () => {
      const state = deactivate({ paths, force: true });
      expect(state.active).toBe(false);
    });

    test("force deactivate recovers when encrypted files are missing", () => {
      const envPath = join(projectDir, ".env");
      writeFileSync(envPath, "SECRET=abc");

      activate({ projectDir, paths });
      expect(existsSync(envPath)).toBe(false);

      // 暗号化ファイルを手動で削除（破損シミュレーション）
      const vaultFiles = readdirSync(paths.vaultDir);
      for (const f of vaultFiles) {
        unlinkSync(join(paths.vaultDir, f));
      }

      // 通常のdeactivateではファイル復元をスキップするが状態はクリアされる
      const state = deactivate({ paths, force: true }) as any;
      expect(state.active).toBe(false);
      // vault stateファイルはクリアされる
      expect(getVaultState(paths)).toBeNull();
    });
  });

  describe("activate + deactivate roundtrip", () => {
    const testDir = join(tmpdir(), `signet-vault-roundtrip-${Date.now()}`);
    let paths: VaultPaths;
    let projectDir: string;

    beforeEach(() => {
      projectDir = join(testDir, "project");
      mkdirSync(projectDir, { recursive: true });
      paths = makeTestPaths(join(testDir, "signet"));
    });

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test(".env content survives roundtrip", () => {
      const envPath = join(projectDir, ".env");
      const original = "SECRET_KEY=abc123\nDB_HOST=localhost\nDEBUG=true";
      writeFileSync(envPath, original);

      activate({ projectDir, paths });
      deactivate(paths);

      expect(readFileSync(envPath, "utf-8")).toBe(original);
    });

    test("env vars survive roundtrip", () => {
      const uniqueVar = `SIGNET_RT_${Date.now()}`;
      process.env[uniqueVar] = "roundtrip-value";

      activate({ projectDir, credentialEnvVars: [uniqueVar], paths });
      deactivate(paths);

      expect(process.env[uniqueVar]).toBe("roundtrip-value");

      delete process.env[uniqueVar];
    });
  });

  describe("retrieveCredential", () => {
    const testDir = join(tmpdir(), `signet-vault-retrieve-${Date.now()}`);
    let paths: VaultPaths;
    let projectDir: string;

    beforeEach(() => {
      projectDir = join(testDir, "project");
      mkdirSync(projectDir, { recursive: true });
      paths = makeTestPaths(join(testDir, "signet"));
    });

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("retrieves evacuated credential", () => {
      const uniqueVar = `SIGNET_RETRIEVE_${Date.now()}`;
      process.env[uniqueVar] = "secret-to-retrieve";

      activate({ projectDir, credentialEnvVars: [uniqueVar], paths });

      const value = retrieveCredential(uniqueVar, paths);
      expect(value).toBe("secret-to-retrieve");

      // クリーンアップ: deactivate で env 復元
      deactivate(paths);
      delete process.env[uniqueVar];
    });

    test("returns null for non-existent credential", () => {
      const value = retrieveCredential("NONEXISTENT_CRED", paths);
      expect(value).toBeNull();
    });
  });

  describe("getVaultState", () => {
    const testDir = join(tmpdir(), `signet-vault-state-${Date.now()}`);
    let paths: VaultPaths;
    let projectDir: string;

    beforeEach(() => {
      projectDir = join(testDir, "project");
      mkdirSync(projectDir, { recursive: true });
      paths = makeTestPaths(join(testDir, "signet"));
    });

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test("returns null before activation", () => {
      expect(getVaultState(paths)).toBeNull();
    });

    test("returns active state after activation", () => {
      activate({ projectDir, paths });

      const state = getVaultState(paths);
      expect(state).not.toBeNull();
      expect(state!.active).toBe(true);
      expect(state!.projectDir).toBe(projectDir);

      // クリーンアップ
      deactivate(paths);
    });

    test("returns null after deactivation", () => {
      activate({ projectDir, paths });
      deactivate(paths);

      expect(getVaultState(paths)).toBeNull();
    });
  });
});
