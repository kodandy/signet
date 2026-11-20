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

# Look the real command up on PATH. This wrapper's own directory is skipped; entries are
# compared as files (-ef), so a trailing slash or a symlinked spelling is still skipped.
# PATH is split by hand because 'read' stops at a newline and would cut an entry short.
# A signet wrapper found elsewhere (a copy of this file) is skipped too: running it would
# evaluate and log the same command again, in a loop.
SELF_DIR=$(cd "$(dirname "$0")" && pwd)
ORIGINAL=""
REST="$PATH:"
while [ -n "$REST" ]; do
  ENTRY="\${REST%%:*}"
  REST="\${REST#*:}"
  if [ -z "$ENTRY" ] || [ "$ENTRY" -ef "$SELF_DIR" ]; then
    continue
  fi
  CANDIDATE="$ENTRY/${cmdName}"
  if [ ! -f "$CANDIDATE" ] || [ ! -x "$CANDIDATE" ]; then
    continue
  fi
  MARKER=""
  { read -r _; read -r MARKER; } < "$CANDIDATE" 2>/dev/null
  if [ "\${MARKER#"# signet wrapper for "}" != "$MARKER" ]; then
    continue
  fi
  ORIGINAL="$CANDIDATE"
  break
done

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
