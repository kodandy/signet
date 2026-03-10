import { describe, test, expect } from "vitest";
import {
  globMatch,
  matchFilesystem,
  matchNetwork,
  matchShell,
  matchCredential,
  matchShellDetailed,
  matchFilesystemDetailed,
  matchNetworkDetailed,
  matchCredentialDetailed,
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

    test("matches IP address when listed in allow", () => {
      const scope = {
        allow: ["192.168.1.1"],
        deny: ["*"],
      };
      expect(matchNetwork(scope, "192.168.1.1")).toBe("allow");
      expect(matchNetwork(scope, "10.0.0.1")).toBe("deny");
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

    test("returns no_match for empty scope object", () => {
      expect(matchShell({}, "ls -la")).toBe("no_match");
    });
  });

  describe("matchFilesystem edge cases", () => {
    test("writable path takes priority over readable for write action", () => {
      const fs = {
        writable: ["./src/**"],
        readable: ["./src/**"],
      };
      expect(matchFilesystem(fs, "./src/foo.ts", "write")).toBe("allow");
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

    test("denies all actions when allowed_actions is empty array", () => {
      const emptyCreds = {
        restricted_key: {
          allowed_actions: [] as string[],
          require_approval: false,
        },
      };
      expect(matchCredential(emptyCreds, "restricted_key", "any action")).toBe("deny");
    });
  });

  // ─── Detailed matchers ───

  describe("matchShellDetailed", () => {
    const shell = {
      deny: ["rm -rf *"],
      ask: ["git push *"],
      allow: ["npm test"],
    };

    test("returns matched rule and category", () => {
      const d = matchShellDetailed(shell, "rm -rf /");
      expect(d.result).toBe("deny");
      expect(d.matchedRule).toBe("rm -rf *");
      expect(d.matchedIn).toBe("deny");
    });

    test("returns ask with matched rule", () => {
      const d = matchShellDetailed(shell, "git push origin main");
      expect(d.result).toBe("ask");
      expect(d.matchedRule).toBe("git push *");
      expect(d.matchedIn).toBe("ask");
    });

    test("returns no_match with no matchedRule", () => {
      const d = matchShellDetailed(shell, "echo hello");
      expect(d.result).toBe("no_match");
      expect(d.matchedRule).toBeUndefined();
    });
  });

  describe("matchFilesystemDetailed", () => {
    const fs = {
      writable: ["./src/**"],
      readable: ["./**"],
      blocked: ["./.env"],
    };

    test("returns blocked rule detail", () => {
      const d = matchFilesystemDetailed(fs, "./.env", "write");
      expect(d.result).toBe("deny");
      expect(d.matchedRule).toBe("./.env");
      expect(d.matchedIn).toBe("blocked");
    });

    test("returns writable match detail", () => {
      const d = matchFilesystemDetailed(fs, "./src/foo.ts", "write");
      expect(d.result).toBe("allow");
      expect(d.matchedRule).toBe("./src/**");
      expect(d.matchedIn).toBe("writable");
    });

    test("returns deny for write outside writable", () => {
      const d = matchFilesystemDetailed(fs, "./dist/out.js", "write");
      expect(d.result).toBe("deny");
      expect(d.matchedIn).toContain("writable");
    });
  });

  describe("matchNetworkDetailed", () => {
    test("returns allow exception detail", () => {
      const net = { allow: ["github.com"], deny: ["*"] };
      const d = matchNetworkDetailed(net, "github.com");
      expect(d.result).toBe("allow");
      expect(d.matchedRule).toBe("github.com");
      expect(d.matchedIn).toContain("exception");
    });

    test("returns deny detail", () => {
      const net = { allow: ["github.com"], deny: ["*"] };
      const d = matchNetworkDetailed(net, "evil.com");
      expect(d.result).toBe("deny");
      expect(d.matchedRule).toBe("*");
    });
  });

  describe("matchCredentialDetailed", () => {
    test("returns require_approval detail", () => {
      const creds = { API_KEY: { require_approval: true } };
      const d = matchCredentialDetailed(creds, "API_KEY");
      expect(d.result).toBe("ask");
      expect(d.matchedIn).toBe("require_approval");
    });

    test("returns not defined for unknown credential", () => {
      const creds = { API_KEY: {} };
      const d = matchCredentialDetailed(creds, "UNKNOWN");
      expect(d.result).toBe("deny");
      expect(d.matchedIn).toBe("not defined");
    });
  });
});
