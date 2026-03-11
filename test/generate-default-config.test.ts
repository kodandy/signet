import { describe, test, expect } from "vitest";
import { generateDefaultConfig } from "../src/index";
import { parse } from "yaml";

describe("generateDefaultConfig", () => {
  const config = generateDefaultConfig();
  const parsed = parse(config);

  test("returns valid YAML", () => {
    expect(parsed).toBeDefined();
    expect(typeof parsed).toBe("object");
  });

  test("has version 1", () => {
    expect(parsed.version).toBe(1);
  });

  test("has 4h default expiry", () => {
    expect(parsed.defaults.expires).toBe("4h");
  });

  test("includes writable dirs: src and test", () => {
    expect(parsed.scope.filesystem.writable).toContain("./src/**");
    expect(parsed.scope.filesystem.writable).toContain("./test/**");
  });

  test("includes readable glob", () => {
    expect(parsed.scope.filesystem.readable).toContain("./**");
  });

  test("blocks .env and sensitive home dirs", () => {
    const blocked = parsed.scope.filesystem.blocked;
    expect(blocked).toContain("./.env");
    expect(blocked).toContain("./.env.*");
    expect(blocked).toContain("~/.ssh/**");
    expect(blocked).toContain("~/.aws/**");
  });

  test("network allows github and npm, denies all else", () => {
    expect(parsed.scope.network.allow).toContain("github.com");
    expect(parsed.scope.network.allow).toContain("registry.npmjs.org");
    expect(parsed.scope.network.deny).toContain("*");
  });

  test("shell deny includes rm -rf and sudo", () => {
    expect(parsed.scope.shell.deny).toContain("rm -rf *");
    expect(parsed.scope.shell.deny).toContain("sudo *");
  });

  test("shell ask includes git push and npm publish", () => {
    expect(parsed.scope.shell.ask).toContain("git push *");
    expect(parsed.scope.shell.ask).toContain("npm publish *");
  });

  test("does not include credential section", () => {
    expect(parsed.scope.credentials).toBeUndefined();
  });
});
