import { parse as parseYaml } from "yaml";
import { readFileSync } from "node:fs";
import type { Scope, SignetConfig, CredentialRule } from "./scope";

interface RawConfig {
  version?: unknown;
  defaults?: unknown;
  scope?: unknown;
}

export function parsePolicy(yamlContent: string): SignetConfig {
  const raw = parseYaml(yamlContent) as RawConfig;

  if (!raw || typeof raw !== "object") {
    throw new Error("Invalid signet config: not an object");
  }

  // version検証
  if (raw.version === undefined) {
    throw new Error("Invalid signet config: missing 'version'");
  }
  if (raw.version !== 1) {
    throw new Error(`Unsupported signet config version: ${raw.version}`);
  }

  // scope検証
  if (!raw.scope || typeof raw.scope !== "object") {
    throw new Error("Invalid signet config: missing 'scope'");
  }

  const scope = validateScope(raw.scope as Record<string, unknown>);
  const defaults = validateDefaults(raw.defaults);

  return {
    version: 1,
    ...(defaults && { defaults }),
    scope,
  };
}

export function parsePolicyFile(filePath: string): SignetConfig {
  const content = readFileSync(filePath, "utf-8");
  return parsePolicy(content);
}

function validateDefaults(
  raw: unknown,
): SignetConfig["defaults"] | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "object") {
    throw new Error("Invalid signet config: 'defaults' must be an object");
  }

  const obj = raw as Record<string, unknown>;
  const result: SignetConfig["defaults"] = {};

  if (obj.expires !== undefined) {
    if (typeof obj.expires !== "string") {
      throw new Error("Invalid signet config: 'defaults.expires' must be a string");
    }
    result.expires = obj.expires;
  }

  return Object.keys(result).length > 0 ? result : undefined;
}

function validateScope(raw: Record<string, unknown>): Scope {
  const scope: Scope = {};

  if (raw.filesystem !== undefined) {
    scope.filesystem = validateStringArrayMap(
      raw.filesystem,
      "scope.filesystem",
      ["writable", "readable", "blocked"],
    );
  }

  if (raw.network !== undefined) {
    scope.network = validateStringArrayMap(
      raw.network,
      "scope.network",
      ["allow", "deny"],
    );
  }

  if (raw.shell !== undefined) {
    scope.shell = validateStringArrayMap(
      raw.shell,
      "scope.shell",
      ["allow", "deny", "ask"],
    );
  }

  if (raw.credentials !== undefined) {
    scope.credentials = validateCredentials(raw.credentials);
  }

  return scope;
}

function validateStringArrayMap<K extends string>(
  raw: unknown,
  path: string,
  allowedKeys: K[],
): Record<K, string[]> {
  if (typeof raw !== "object" || raw === null) {
    throw new Error(`Invalid signet config: '${path}' must be an object`);
  }

  const obj = raw as Record<string, unknown>;
  const result: Record<string, string[]> = {};

  for (const key of allowedKeys) {
    if (obj[key] !== undefined) {
      if (!Array.isArray(obj[key])) {
        throw new Error(`Invalid signet config: '${path}.${key}' must be an array`);
      }
      const arr = obj[key] as unknown[];
      for (let i = 0; i < arr.length; i++) {
        if (typeof arr[i] !== "string") {
          throw new Error(
            `Invalid signet config: '${path}.${key}[${i}]' must be a string`,
          );
        }
      }
      result[key] = arr as string[];
    }
  }

  return result as Record<K, string[]>;
}

function validateCredentials(
  raw: unknown,
): Record<string, CredentialRule> {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Invalid signet config: 'scope.credentials' must be an object");
  }

  const obj = raw as Record<string, unknown>;
  const result: Record<string, CredentialRule> = {};

  for (const [name, value] of Object.entries(obj)) {
    if (typeof value !== "object" || value === null) {
      throw new Error(
        `Invalid signet config: 'scope.credentials.${name}' must be an object`,
      );
    }

    const cred = value as Record<string, unknown>;
    const rule: CredentialRule = {};

    if (cred.source !== undefined) {
      if (typeof cred.source !== "string") {
        throw new Error(
          `Invalid signet config: 'scope.credentials.${name}.source' must be a string`,
        );
      }
      rule.source = cred.source;
    }

    if (cred.allowed_actions !== undefined) {
      if (!Array.isArray(cred.allowed_actions)) {
        throw new Error(
          `Invalid signet config: 'scope.credentials.${name}.allowed_actions' must be an array`,
        );
      }
      rule.allowed_actions = cred.allowed_actions as string[];
    }

    if (cred.max_uses !== undefined) {
      if (typeof cred.max_uses !== "number") {
        throw new Error(
          `Invalid signet config: 'scope.credentials.${name}.max_uses' must be a number`,
        );
      }
      rule.max_uses = cred.max_uses;
    }

    if (cred.expires !== undefined) {
      if (typeof cred.expires !== "string") {
        throw new Error(
          `Invalid signet config: 'scope.credentials.${name}.expires' must be a string`,
        );
      }
      rule.expires = cred.expires;
    }

    if (cred.require_approval !== undefined) {
      if (typeof cred.require_approval !== "boolean") {
        throw new Error(
          `Invalid signet config: 'scope.credentials.${name}.require_approval' must be a boolean`,
        );
      }
      rule.require_approval = cred.require_approval;
    }

    result[name] = rule;
  }

  return result;
}
