import { describe, test, expect } from "vitest";
import { parsePolicy } from "../src/policy/parser";

// ARCHITECTURE.mdのsignet.yml例
const fullYaml = `
version: 1
defaults:
  expires: "4h"

scope:
  filesystem:
    writable:
      - "./src/**"
      - "./test/**"
      - "./docs/**"
    readable:
      - "./**"
    blocked:
      - "./.env"
      - "./.env.*"
      - "~/.ssh/**"
      - "~/.aws/**"

  network:
    allow:
      - "github.com"
      - "registry.npmjs.org"
      - "api.anthropic.com"
    deny:
      - "*"

  credentials:
    github_token:
      source: "env:GITHUB_TOKEN"
      allowed_actions:
        - "git push"
        - "gh pr create"
      max_uses: 10
      require_approval: false

    aws:
      source: "file:~/.aws/credentials"
      allowed_actions:
        - "aws s3 ls"
      require_approval: true

  shell:
    deny:
      - "rm -rf *"
      - "sudo *"
      - "chmod 777 *"
    ask:
      - "git push *"
      - "npm publish *"
`;

describe("policy/parser", () => {
  describe("parsePolicy", () => {
    test("parses the full signet.yml example from ARCHITECTURE.md", () => {
      const config = parsePolicy(fullYaml);

      expect(config.version).toBe(1);
      expect(config.defaults?.expires).toBe("4h");
      expect(config.scope.filesystem?.writable).toEqual([
        "./src/**",
        "./test/**",
        "./docs/**",
      ]);
      expect(config.scope.filesystem?.readable).toEqual(["./**"]);
      expect(config.scope.filesystem?.blocked).toEqual([
        "./.env",
        "./.env.*",
        "~/.ssh/**",
        "~/.aws/**",
      ]);
      expect(config.scope.network?.allow).toEqual([
        "github.com",
        "registry.npmjs.org",
        "api.anthropic.com",
      ]);
      expect(config.scope.network?.deny).toEqual(["*"]);
      expect(config.scope.credentials?.github_token).toEqual({
        source: "env:GITHUB_TOKEN",
        allowed_actions: ["git push", "gh pr create"],
        max_uses: 10,
        require_approval: false,
      });
      expect(config.scope.credentials?.aws).toEqual({
        source: "file:~/.aws/credentials",
        allowed_actions: ["aws s3 ls"],
        require_approval: true,
      });
      expect(config.scope.shell?.deny).toEqual([
        "rm -rf *",
        "sudo *",
        "chmod 777 *",
      ]);
      expect(config.scope.shell?.ask).toEqual([
        "git push *",
        "npm publish *",
      ]);
    });

    test("parses minimal config", () => {
      const config = parsePolicy(`
version: 1
scope:
  shell:
    deny:
      - "rm -rf /"
`);

      expect(config.version).toBe(1);
      expect(config.defaults).toBeUndefined();
      expect(config.scope.shell?.deny).toEqual(["rm -rf /"]);
      expect(config.scope.filesystem).toBeUndefined();
    });

    test("throws on missing version", () => {
      expect(() =>
        parsePolicy(`
scope:
  shell:
    deny: ["rm"]
`),
      ).toThrow("missing 'version'");
    });

    test("throws on unsupported version", () => {
      expect(() =>
        parsePolicy(`
version: 2
scope:
  shell:
    deny: ["rm"]
`),
      ).toThrow("Unsupported signet config version: 2");
    });

    test("throws on missing scope", () => {
      expect(() =>
        parsePolicy(`
version: 1
`),
      ).toThrow("missing 'scope'");
    });

    test("throws on invalid YAML", () => {
      expect(() => parsePolicy("{{{{invalid")).toThrow();
    });

    test("throws on non-array shell.deny", () => {
      expect(() =>
        parsePolicy(`
version: 1
scope:
  shell:
    deny: "not-an-array"
`),
      ).toThrow("must be an array");
    });

    test("throws on non-string array element", () => {
      expect(() =>
        parsePolicy(`
version: 1
scope:
  shell:
    deny:
      - 123
`),
      ).toThrow("must be a string");
    });
  });
});
