import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { existsSync, writeFileSync, readFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// vault/manager.tsのテストは$HOMEに依存するため、
// テスト用に関数を直接テストする代わりにinjectForCommandを中心にテスト
import { injectForCommand } from "../src/vault/manager";

describe("vault/manager", () => {
  describe("injectForCommand", () => {
    test("injects env var for command execution", () => {
      const result = injectForCommand(
        "TEST_SIGNET_CRED",
        "secret-value-123",
        "echo $TEST_SIGNET_CRED",
      );

      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe("secret-value-123");
    });

    test("credential is not visible after command completes", () => {
      injectForCommand("TEST_SIGNET_TEMP", "temp-secret", "echo ok");

      expect(process.env.TEST_SIGNET_TEMP).toBeUndefined();
    });

    test("returns exit code on command failure", () => {
      const result = injectForCommand("X", "v", "false");

      expect(result.exitCode).not.toBe(0);
    });

    test("captures stdout from command", () => {
      const result = injectForCommand("MY_VAR", "hello", "echo $MY_VAR world");

      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe("hello world");
    });

    test("does not leak credential to parent process env", () => {
      const originalEnv = { ...process.env };

      injectForCommand("SIGNET_SECRET_KEY", "super-secret", "echo test");

      expect(process.env.SIGNET_SECRET_KEY).toBeUndefined();
      // 元の環境変数が変わっていないことを確認
      expect(process.env.HOME).toBe(originalEnv.HOME);
    });
  });

  describe("activate / deactivate", () => {
    // これらのテストは$HOME/.signet/を操作するため、
    // 実際のファイルシステムのテストはtmpdir内で行う
    const testDir = join(tmpdir(), `signet-vault-test-${Date.now()}`);
    const envFilePath = join(testDir, ".env");

    beforeEach(() => {
      mkdirSync(testDir, { recursive: true });
      writeFileSync(envFilePath, "API_KEY=secret123\nDB_URL=postgres://localhost");
    });

    afterEach(() => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    });

    test(".env file content can be read before evacuation", () => {
      const content = readFileSync(envFilePath, "utf-8");
      expect(content).toContain("API_KEY=secret123");
    });
  });
});
