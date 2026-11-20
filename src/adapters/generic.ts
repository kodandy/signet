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
 *   3. ラッパーがsignet evalを通してから実コマンドを実行（判定は監査ログに残る）
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
    // コマンド名はファイル名とスクリプト本文に入る。パス区切りやシェルの特殊文字を含むものは生成しない
    if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(cmdName)) continue;

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

# Look the real command up on PATH without this wrapper's own directory. Entries are
# compared as files (-ef), so a trailing slash or a symlinked spelling is still removed.
SELF_DIR=$(cd "$(dirname "$0")" && pwd)
CLEAN_PATH=""
IFS=':' read -r -a PATH_ENTRIES <<< "$PATH"
for ENTRY in "\${PATH_ENTRIES[@]}"; do
  if [ -z "$ENTRY" ] || [ "$ENTRY" -ef "$SELF_DIR" ]; then
    continue
  fi
  CLEAN_PATH="\${CLEAN_PATH:+$CLEAN_PATH:}$ENTRY"
done

ORIGINAL=$(PATH="$CLEAN_PATH" which ${cmdName} 2>/dev/null)

# Never exec this wrapper again: that would evaluate and log the same command in a loop.
if [ -n "$ORIGINAL" ] && [ "$ORIGINAL" -ef "$0" ]; then
  ORIGINAL=""
fi

if [ -z "$ORIGINAL" ]; then
  echo "signet: original '${cmdName}' not found in PATH" >&2
  exit 127
fi

# Build the full command string for policy check. Empty arguments are skipped so that
# they cannot add a space that moves the string past a deny pattern.
FULL_CMD="${cmdName}"
for ARG in "$@"; do
  if [ -n "$ARG" ]; then
    FULL_CMD="$FULL_CMD $ARG"
  fi
done

# Evaluate with signet. 'signet eval' signs the request, records the decision in the
# audit log, and exits 0 only when the command is allowed. It needs SIGNET_AGENT and
# SIGNET_TOKEN; without them it exits 2. Anything but 0 blocks the command, and so does
# a missing signet: a wrapper that cannot ask must not run the command.
if ! command -v signet &>/dev/null; then
  echo "signet: signet not found in PATH, command blocked: $FULL_CMD" >&2
  exit 1
fi

signet eval "$FULL_CMD" >/dev/null
EVAL_RESULT=$?
if [ $EVAL_RESULT -ne 0 ]; then
  echo "signet: command blocked (exit $EVAL_RESULT): $FULL_CMD" >&2
  exit 1
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
