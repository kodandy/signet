import { describe, test, expect } from "vitest";
import {
  globMatch,
  matchFilesystem,
  matchNetwork,
  matchShell,
  matchCredential,
} from "../src/policy/matcher";

describe("policy/matcher", () => {
  describe("globMatch", () => {
    test("exact match", () => {
      expect(globMatch("foo.txt", "foo.txt")).toBe(true);
      expect(globMatch("foo.txt", "bar.txt")).toBe(false);
    });

    test("* matches any chars except /", () => {
      expect(globMatch("*.ts", "keys.ts")).toBe(true);
      expect(globMatch("*.ts", "src/keys.ts")).toBe(false);
      expect(globMatch("src/*.ts", "src/keys.ts")).toBe(true);
    });

    test("** matches across directories", () => {
      expect(globMatch("./src/**", "./src/crypto/keys.ts")).toBe(true);
      expect(globMatch("./src/**", "./src/a/b/c.ts")).toBe(true);
      expect(globMatch("./src/**", "./test/foo.ts")).toBe(false);
    });

    test("? matches single char", () => {
      expect(globMatch("?.ts", "a.ts")).toBe(true);
      expect(globMatch("?.ts", "ab.ts")).toBe(false);
    });

    test("escapes regex special chars", () => {
      expect(globMatch("./.env", "./.env")).toBe(true);
      expect(globMatch("./.env.*", "./.env.local")).toBe(true);
    });

    test("multiple ** in pattern", () => {
      expect(globMatch("a/**/b/**/c.ts", "a/x/b/y/c.ts")).toBe(true);
      expect(globMatch("a/**/b/**/c.ts", "a/x/y/b/z/c.ts")).toBe(true);
    });

    test("empty pattern matches empty string", () => {
      expect(globMatch("", "")).toBe(true);
      expect(globMatch("", "foo")).toBe(false);
    });
  });

  describe("matchFilesystem", () => {
    const fs = {
      writable: ["./src/**", "./test/**"],
      readable: ["./**"],
      blocked: ["./.env", "./.env.*", "~/.ssh/**"],
    };

    test("blocks .env (highest priority)", () => {
      expect(matchFilesystem(fs, "./.env", "read")).toBe("deny");
      expect(matchFilesystem(fs, "./.env", "write")).toBe("deny");
      expect(matchFilesystem(fs, "./.env.local", "read")).toBe("deny");
    });

    test("blocks ~/.ssh paths", () => {
      expect(matchFilesystem(fs, "~/.ssh/id_rsa", "read")).toBe("deny");
    });

    test("allows write to src/", () => {
      expect(matchFilesystem(fs, "./src/crypto/keys.ts", "write")).toBe("allow");
      expect(matchFilesystem(fs, "./test/foo.test.ts", "write")).toBe("allow");
    });

    test("denies write outside writable paths", () => {
      expect(matchFilesystem(fs, "./package.json", "write")).toBe("deny");
      expect(matchFilesystem(fs, "/etc/passwd", "write")).toBe("deny");
    });

    test("allows read via readable glob", () => {
      expect(matchFilesystem(fs, "./package.json", "read")).toBe("allow");
      expect(matchFilesystem(fs, "./README.md", "read")).toBe("allow");
    });

    test("returns no_match when scope is undefined", () => {
      expect(matchFilesystem(undefined, "./src/foo.ts", "read")).toBe("no_match");
    });
  });

  describe("matchNetwork", () => {
    const net = {
      allow: ["github.com", "registry.npmjs.org", "api.anthropic.com"],
      deny: ["*"],
    };

    test("allows whitelisted domains despite deny *", () => {
      expect(matchNetwork(net, "github.com")).toBe("allow");
      expect(matchNetwork(net, "registry.npmjs.org")).toBe("allow");
    });

    test("denies non-whitelisted domains", () => {
      expect(matchNetwork(net, "evil.com")).toBe("deny");
      expect(matchNetwork(net, "random.io")).toBe("deny");
    });

    test("supports wildcard subdomain matching", () => {
      const scope = {
        allow: ["*.github.com"],
        deny: ["*"],
      };
      expect(matchNetwork(scope, "api.github.com")).toBe("allow");
      expect(matchNetwork(scope, "raw.github.com")).toBe("allow");
      expect(matchNetwork(scope, "github.com")).toBe("deny");
    });

    test("returns no_match when scope is undefined", () => {
      expect(matchNetwork(undefined, "example.com")).toBe("no_match");
    });
  });

  describe("matchShell", () => {
    const shell = {
      deny: ["rm -rf *", "sudo *", "chmod 777 *"],
      ask: ["git push *", "npm publish *"],
    };

    test("denies dangerous commands", () => {
      expect(matchShell(shell, "rm -rf /")).toBe("deny");
      expect(matchShell(shell, "sudo apt install foo")).toBe("deny");
      expect(matchShell(shell, "chmod 777 /etc/passwd")).toBe("deny");
    });

    test("asks for approval on git push", () => {
      expect(matchShell(shell, "git push origin main")).toBe("ask");
      expect(matchShell(shell, "npm publish --access public")).toBe("ask");
    });

    test("returns no_match for unmatched commands", () => {
      expect(matchShell(shell, "ls -la")).toBe("no_match");
      expect(matchShell(shell, "npm install express")).toBe("no_match");
    });

    test("allow takes effect when defined", () => {
      const withAllow = {
        allow: ["npm install *", "npm test"],
        deny: ["npm publish *"],
      };
      expect(matchShell(withAllow, "npm install express")).toBe("allow");
      expect(matchShell(withAllow, "npm test")).toBe("allow");
      expect(matchShell(withAllow, "npm publish foo")).toBe("deny");
    });

    test("deny takes priority over ask and allow", () => {
      const mixed = {
        allow: ["rm *"],
        ask: ["rm *"],
        deny: ["rm *"],
      };
      expect(matchShell(mixed, "rm foo")).toBe("deny");
    });

    test("returns no_match when scope is undefined", () => {
      expect(matchShell(undefined, "ls")).toBe("no_match");
    });
  });

  describe("matchCredential", () => {
    const creds = {
      github_token: {
        allowed_actions: ["git push", "gh pr create"],
        max_uses: 10,
        require_approval: false,
      },
      aws: {
        allowed_actions: ["aws s3 ls"],
        require_approval: true,
      },
    };

    test("allows github_token for permitted actions", () => {
      expect(matchCredential(creds, "github_token", "git push")).toBe("allow");
      expect(matchCredential(creds, "github_token", "gh pr create")).toBe("allow");
    });

    test("denies github_token for non-permitted actions", () => {
      expect(matchCredential(creds, "github_token", "git force-push")).toBe("deny");
    });

    test("asks for approval on aws credential", () => {
      expect(matchCredential(creds, "aws", "aws s3 ls")).toBe("ask");
    });

    test("denies aws credential for non-permitted actions", () => {
      expect(matchCredential(creds, "aws", "aws ec2 terminate")).toBe("deny");
    });

    test("denies unknown credential", () => {
      expect(matchCredential(creds, "unknown_key", "action")).toBe("deny");
    });

    test("returns no_match when scope is undefined", () => {
      expect(matchCredential(undefined, "github_token")).toBe("no_match");
    });

    test("allows when no action specified and no require_approval", () => {
      expect(matchCredential(creds, "github_token")).toBe("allow");
    });
  });
});
