import { describe, test, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parsePolicy } from "../src/policy/parser";

const templatesDir = join(__dirname, "..", "templates");

describe("templates", () => {
  for (const name of ["general", "node", "python"]) {
    test(`${name}.yml is valid signet config`, () => {
      const content = readFileSync(join(templatesDir, `${name}.yml`), "utf-8");
      const config = parsePolicy(content);

      expect(config.version).toBe(1);
      expect(config.scope).toBeDefined();
      expect(config.scope.filesystem?.blocked).toBeDefined();
      expect(config.scope.filesystem?.blocked!.length).toBeGreaterThan(0);
      expect(config.scope.shell?.deny).toBeDefined();
    });
  }

  test("node template has npm-specific rules", () => {
    const content = readFileSync(join(templatesDir, "node.yml"), "utf-8");
    const config = parsePolicy(content);

    expect(config.scope.credentials?.npm_token).toBeDefined();
    expect(config.scope.credentials?.npm_token.require_approval).toBe(true);
    expect(config.scope.network?.allow).toContain("registry.npmjs.org");
  });

  test("python template has pypi-specific rules", () => {
    const content = readFileSync(join(templatesDir, "python.yml"), "utf-8");
    const config = parsePolicy(content);

    expect(config.scope.credentials?.pypi_token).toBeDefined();
    expect(config.scope.network?.allow).toContain("pypi.org");
  });

  for (const name of ["general", "node", "python"]) {
    test(`${name}.yml blocks data exfiltration commands`, () => {
      const content = readFileSync(join(templatesDir, `${name}.yml`), "utf-8");
      const config = parsePolicy(content);
      const denyList = config.scope.shell?.deny ?? [];

      // データ送信コマンドがdenyリストに含まれていること
      expect(denyList).toContain("curl *");
      expect(denyList).toContain("wget *");
      expect(denyList).toContain("nc *");
      // 環境変数表示コマンドがdenyリストに含まれていること
      expect(denyList).toContain("env");
      expect(denyList).toContain("printenv *");
    });
  }
});
