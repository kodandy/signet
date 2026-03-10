import type { Scope } from "./scope";

export type MatchResult = "allow" | "deny" | "ask" | "no_match";

/**
 * シンプルなglob風パターンマッチング。
 * サポート: `*`(任意文字列、/除く), `**`(任意パス含む), `?`(任意1文字)
 */
export function globMatch(pattern: string, target: string): boolean {
  const regex = globToRegex(pattern);
  return regex.test(target);
}

function globToRegex(pattern: string): RegExp {
  let i = 0;
  let result = "^";

  while (i < pattern.length) {
    const c = pattern[i];

    if (c === "*" && pattern[i + 1] === "*") {
      // ** は任意のパス（/を含む）にマッチ
      result += ".*";
      i += 2;
      // 後続の / をスキップ
      if (pattern[i] === "/") i++;
    } else if (c === "*") {
      // * は / を除く任意の文字列にマッチ
      result += "[^/]*";
      i++;
    } else if (c === "?") {
      result += "[^/]";
      i++;
    } else if (".+^${}()|[]\\".includes(c)) {
      result += "\\" + c;
      i++;
    } else {
      result += c;
      i++;
    }
  }

  result += "$";
  return new RegExp(result);
}

/**
 * ファイルシステムパスのマッチング。
 * 優先順: blocked → writable/readable → no_match
 */
export function matchFilesystem(
  scope: Scope["filesystem"],
  path: string,
  action: "read" | "write",
): MatchResult {
  if (!scope) return "no_match";

  // blocked は最優先で拒否
  if (scope.blocked?.some((p) => globMatch(p, path))) {
    return "deny";
  }

  if (action === "write") {
    if (scope.writable?.some((p) => globMatch(p, path))) return "allow";
    // writable定義があるのにマッチしない → deny
    if (scope.writable && scope.writable.length > 0) return "deny";
  }

  if (action === "read") {
    if (scope.readable?.some((p) => globMatch(p, path))) return "allow";
    // readableが未定義ならwritableもチェック
    if (scope.writable?.some((p) => globMatch(p, path))) return "allow";
  }

  return "no_match";
}

/**
 * ネットワークドメインのマッチング。
 * 優先順: deny → allow → デフォルトdeny
 */
export function matchNetwork(
  scope: Scope["network"],
  domain: string,
): MatchResult {
  if (!scope) return "no_match";

  if (scope.deny?.some((p) => domainMatch(p, domain))) {
    // "*" は全拒否だが、allowリストで例外指定可能
    if (
      scope.deny.some((p) => p === "*") &&
      scope.allow?.some((p) => domainMatch(p, domain))
    ) {
      return "allow";
    }
    return "deny";
  }

  if (scope.allow?.some((p) => domainMatch(p, domain))) {
    return "allow";
  }

  return "no_match";
}

function domainMatch(pattern: string, domain: string): boolean {
  if (pattern === "*") return true;
  if (pattern === domain) return true;
  // *.example.com はサブドメインにマッチ
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // .example.com
    return domain.endsWith(suffix);
  }
  return false;
}

/**
 * シェルコマンドのマッチング。
 * 優先順: deny → ask → allow → no_match
 */
export function matchShell(
  scope: Scope["shell"],
  command: string,
): MatchResult {
  if (!scope) return "no_match";

  if (scope.deny?.some((p) => commandMatch(p, command))) {
    return "deny";
  }

  if (scope.ask?.some((p) => commandMatch(p, command))) {
    return "ask";
  }

  if (scope.allow?.some((p) => commandMatch(p, command))) {
    return "allow";
  }

  return "no_match";
}

function commandMatch(pattern: string, command: string): boolean {
  // コマンドパターンでは * が / を含む全文字にマッチ（ファイルパスではなくコマンド引数のため）
  const regex = commandGlobToRegex(pattern);
  return regex.test(command);
}

function commandGlobToRegex(pattern: string): RegExp {
  let i = 0;
  let result = "^";

  while (i < pattern.length) {
    const c = pattern[i];

    if (c === "*") {
      // コマンドパターンの * は全文字にマッチ
      result += ".*";
      i++;
    } else if (c === "?") {
      result += ".";
      i++;
    } else if (".+^${}()|[]\\".includes(c)) {
      result += "\\" + c;
      i++;
    } else {
      result += c;
      i++;
    }
  }

  result += "$";
  return new RegExp(result);
}

/**
 * クレデンシャル使用のマッチング。
 */
export function matchCredential(
  scope: Scope["credentials"],
  credName: string,
  action?: string,
): MatchResult {
  if (!scope) return "no_match";

  const rule = scope[credName];
  if (!rule) return "deny";

  // allowed_actionsが定義されていてアクション指定がある場合（空配列は全拒否）
  if (action && rule.allowed_actions) {
    const actionAllowed = rule.allowed_actions.some((p) =>
      globMatch(p, action),
    );
    if (!actionAllowed) return "deny";
  }

  if (rule.require_approval) return "ask";
  return "allow";
}

// ─── DetailedMatch: マッチしたルール情報を返す拡張版 ───

export interface MatchDetail {
  result: MatchResult;
  matchedRule?: string;   // マッチしたパターン文字列
  matchedIn?: string;     // マッチしたルールカテゴリ (e.g. "deny", "allow", "blocked")
}

export function matchShellDetailed(scope: Scope["shell"], command: string): MatchDetail {
  if (!scope) return { result: "no_match" };
  const denyMatch = scope.deny?.find((p) => commandMatch(p, command));
  if (denyMatch) return { result: "deny", matchedRule: denyMatch, matchedIn: "deny" };
  const askMatch = scope.ask?.find((p) => commandMatch(p, command));
  if (askMatch) return { result: "ask", matchedRule: askMatch, matchedIn: "ask" };
  const allowMatch = scope.allow?.find((p) => commandMatch(p, command));
  if (allowMatch) return { result: "allow", matchedRule: allowMatch, matchedIn: "allow" };
  return { result: "no_match" };
}

export function matchFilesystemDetailed(scope: Scope["filesystem"], path: string, action: "read" | "write"): MatchDetail {
  if (!scope) return { result: "no_match" };
  const blockedMatch = scope.blocked?.find((p) => globMatch(p, path));
  if (blockedMatch) return { result: "deny", matchedRule: blockedMatch, matchedIn: "blocked" };
  if (action === "write") {
    const writableMatch = scope.writable?.find((p) => globMatch(p, path));
    if (writableMatch) return { result: "allow", matchedRule: writableMatch, matchedIn: "writable" };
    if (scope.writable && scope.writable.length > 0) return { result: "deny", matchedIn: "writable (no match)" };
  }
  if (action === "read") {
    const readableMatch = scope.readable?.find((p) => globMatch(p, path));
    if (readableMatch) return { result: "allow", matchedRule: readableMatch, matchedIn: "readable" };
    const writableMatch = scope.writable?.find((p) => globMatch(p, path));
    if (writableMatch) return { result: "allow", matchedRule: writableMatch, matchedIn: "writable" };
  }
  return { result: "no_match" };
}

export function matchNetworkDetailed(scope: Scope["network"], domain: string): MatchDetail {
  if (!scope) return { result: "no_match" };
  if (scope.deny?.some((p) => domainMatch(p, domain))) {
    if (scope.deny.some((p) => p === "*") && scope.allow?.some((p) => domainMatch(p, domain))) {
      const allowMatch = scope.allow!.find((p) => domainMatch(p, domain))!;
      return { result: "allow", matchedRule: allowMatch, matchedIn: "allow (exception)" };
    }
    const denyMatch = scope.deny.find((p) => domainMatch(p, domain))!;
    return { result: "deny", matchedRule: denyMatch, matchedIn: "deny" };
  }
  const allowMatch = scope.allow?.find((p) => domainMatch(p, domain));
  if (allowMatch) return { result: "allow", matchedRule: allowMatch, matchedIn: "allow" };
  return { result: "no_match" };
}

export function matchCredentialDetailed(scope: Scope["credentials"], credName: string, action?: string): MatchDetail {
  if (!scope) return { result: "no_match" };
  const rule = scope[credName];
  if (!rule) return { result: "deny", matchedIn: "not defined" };
  if (action && rule.allowed_actions) {
    const actionMatch = rule.allowed_actions.find((p) => globMatch(p, action));
    if (!actionMatch) return { result: "deny", matchedIn: "allowed_actions (no match)" };
  }
  if (rule.require_approval) return { result: "ask", matchedRule: credName, matchedIn: "require_approval" };
  return { result: "allow", matchedRule: credName, matchedIn: "credentials" };
}
