import { existsSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import type { Scope } from "../policy/scope";

/**
 * Generic adapter
 * PATH差し替え + 環境変数プロキシで汎用エージェントに対応
 *
 * 仕組み:
 *   1. ~/.signet/bin/ にラッパースクリプトを生成
 *   2. PATHの先頭に~/.signet/bin/を追加
 *   3. ラッパーがsignet checkを通してから実コマンドを実行
 */
export function generateWrappers(
  scope: Scope,
  binDir: string,
): string[] {
  if (!existsSync(binDir)) {
    mkdirSync(binDir, { recursive: true, mode: 0o700 });
  }

  const wrappedCommands: string[] = [];

  // shell.deny + shell.ask で指定されたコマンドのベース名を抽出
  const commandPatterns = [
    ...(scope.shell?.deny ?? []),
    ...(scope.shell?.ask ?? []),
  ];

  for (const pattern of commandPatterns) {
    // パターンの最初のワード = コマンド名
    const cmdName = pattern.split(" ")[0];
    if (!cmdName || cmdName === "*") continue;

    const wrapperPath = join(binDir, cmdName);
    if (wrappedCommands.includes(cmdName)) continue;

    const script = generateWrapperScript(cmdName);
    writeFileSync(wrapperPath, script, { mode: 0o755 });
    wrappedCommands.push(cmdName);
  }

  return wrappedCommands;
}

function generateWrapperScript(cmdName: string): string {
  return `#!/usr/bin/env bash
# signet wrapper for ${cmdName}
# Intercepts command execution for policy checking

ORIGINAL=$(PATH=$(echo "$PATH" | sed "s|$HOME/.signet/bin:||g") which ${cmdName} 2>/dev/null)

if [ -z "$ORIGINAL" ]; then
  echo "signet: original '${cmdName}' not found in PATH" >&2
  exit 127
fi

# Build the full command string for policy check
FULL_CMD="${cmdName} $*"

# Check with signet (if available)
if command -v signet &>/dev/null; then
  signet check "$FULL_CMD" 2>/dev/null
  CHECK_RESULT=$?
  if [ $CHECK_RESULT -ne 0 ]; then
    echo "signet: command blocked by policy: $FULL_CMD" >&2
    exit 1
  fi
fi

# Execute original command
exec "$ORIGINAL" "$@"
`;
}

/**
 * PATHに~/.signet/bin/を先頭に追加するための環境設定を生成
 */
export function generatePathSetup(binDir: string): string {
  return `export PATH="${binDir}:$PATH"`;
}
