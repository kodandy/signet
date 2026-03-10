import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { homedir } from "node:os";
import { execSync } from "node:child_process";
import { createHash, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

const DEFAULT_VAULT_DIR = join(homedir(), ".signet", "vault");
const DEFAULT_VAULT_KEY_PATH = join(homedir(), ".signet", "vault.key");
const DEFAULT_STATE_PATH = join(homedir(), ".signet", "vault-state.json");
const COMMAND_TIMEOUT_MS = 30_000;

export interface VaultPaths {
  vaultDir: string;
  vaultKeyPath: string;
  statePath: string;
}

export interface VaultConfig {
  envFiles?: string[];             // 退避する.envファイルパス (デフォルト: [".env"])
  credentialEnvVars?: string[];    // 退避する環境変数名
  projectDir?: string;             // プロジェクトルート (デフォルト: cwd)
  paths?: Partial<VaultPaths>;     // テスト・カスタム用パスオーバーライド
}

export interface VaultState {
  active: boolean;
  evacuatedFiles: string[];
  evacuatedVars: string[];
  projectDir: string;
}

function resolvePaths(overrides?: Partial<VaultPaths>): VaultPaths {
  return {
    vaultDir: overrides?.vaultDir ?? DEFAULT_VAULT_DIR,
    vaultKeyPath: overrides?.vaultKeyPath ?? DEFAULT_VAULT_KEY_PATH,
    statePath: overrides?.statePath ?? DEFAULT_STATE_PATH,
  };
}

function getVaultKey(vaultKeyPath: string): Buffer {
  if (!existsSync(vaultKeyPath)) {
    const dir = dirname(vaultKeyPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const key = randomBytes(32);
    writeFileSync(vaultKeyPath, key, { mode: 0o600 });
    return key;
  }
  return readFileSync(vaultKeyPath);
}

function encrypt(data: string, vaultKeyPath: string): string {
  const key = getVaultKey(vaultKeyPath);
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(data, "utf-8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(data: string, vaultKeyPath: string): string {
  const key = getVaultKey(vaultKeyPath);
  const parts = data.split(":");
  if (parts.length !== 2) {
    throw new Error("Invalid encrypted data format: expected 'iv:ciphertext'");
  }
  const [ivHex, encrypted] = parts;
  const iv = Buffer.from(ivHex, "hex");
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}

function loadState(statePath: string): VaultState | null {
  if (!existsSync(statePath)) return null;
  return JSON.parse(readFileSync(statePath, "utf-8")) as VaultState;
}

function saveState(state: VaultState, statePath: string): void {
  const dir = dirname(statePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  writeFileSync(statePath, JSON.stringify(state, null, 2), { mode: 0o600 });
}

function clearState(statePath: string): void {
  if (existsSync(statePath)) unlinkSync(statePath);
}

/**
 * Vault有効化: .envファイルを退避、環境変数をクリア
 */
export function activate(config: VaultConfig = {}): VaultState {
  const paths = resolvePaths(config.paths);
  const existing = loadState(paths.statePath);
  if (existing?.active) {
    throw new Error("Vault is already active. Run deactivate first.");
  }

  const projectDir = resolve(config.projectDir ?? process.cwd());
  const envFiles = config.envFiles ?? [".env"];
  const evacuatedFiles: string[] = [];
  const evacuatedVars: string[] = [];

  if (!existsSync(paths.vaultDir)) {
    mkdirSync(paths.vaultDir, { recursive: true, mode: 0o700 });
  }

  // 1. .envファイルを暗号化して退避
  for (const envFile of envFiles) {
    const fullPath = resolve(projectDir, envFile);
    if (existsSync(fullPath)) {
      const content = readFileSync(fullPath, "utf-8");
      const hash = createHash("sha256").update(fullPath).digest("hex").slice(0, 16);
      const vaultPath = join(paths.vaultDir, `${hash}.enc`);

      writeFileSync(vaultPath, encrypt(content, paths.vaultKeyPath), { mode: 0o600 });
      writeFileSync(vaultPath + ".meta", JSON.stringify({ originalPath: fullPath }), { mode: 0o600 });
      unlinkSync(fullPath);
      evacuatedFiles.push(fullPath);
    }
  }

  // 2. 指定された環境変数を退避
  if (config.credentialEnvVars) {
    for (const varName of config.credentialEnvVars) {
      if (process.env[varName] !== undefined) {
        const vaultPath = join(paths.vaultDir, `env_${varName}.enc`);
        writeFileSync(vaultPath, encrypt(process.env[varName]!, paths.vaultKeyPath), { mode: 0o600 });
        delete process.env[varName];
        evacuatedVars.push(varName);
      }
    }
  }

  const state: VaultState = {
    active: true,
    evacuatedFiles,
    evacuatedVars,
    projectDir,
  };

  saveState(state, paths.statePath);
  return state;
}

/**
 * Vault無効化: 退避したファイルと環境変数を復元
 */
export function deactivate(pathOverrides?: Partial<VaultPaths>): VaultState {
  const paths = resolvePaths(pathOverrides);
  const state = loadState(paths.statePath);
  if (!state?.active) {
    throw new Error("Vault is not active.");
  }

  // 1. .envファイルを復元
  for (const filePath of state.evacuatedFiles) {
    const hash = createHash("sha256").update(filePath).digest("hex").slice(0, 16);
    const vaultPath = join(paths.vaultDir, `${hash}.enc`);

    if (existsSync(vaultPath)) {
      const content = decrypt(readFileSync(vaultPath, "utf-8"), paths.vaultKeyPath);
      writeFileSync(filePath, content, { mode: 0o600 });
      unlinkSync(vaultPath);
      const metaPath = vaultPath + ".meta";
      if (existsSync(metaPath)) unlinkSync(metaPath);
    }
  }

  // 2. 環境変数を復元
  for (const varName of state.evacuatedVars) {
    const vaultPath = join(paths.vaultDir, `env_${varName}.enc`);
    if (existsSync(vaultPath)) {
      const value = decrypt(readFileSync(vaultPath, "utf-8"), paths.vaultKeyPath);
      process.env[varName] = value;
      unlinkSync(vaultPath);
    }
  }

  clearState(paths.statePath);

  return { ...state, active: false };
}

const REDACTED = "[SIGNET:REDACTED]";

/**
 * 出力から秘密値をマスクする
 */
function redactSecret(output: string, secret: string): string {
  if (!secret || secret.length < 4) return output;
  let result = output;
  // 平文の秘密値を置換
  while (result.includes(secret)) {
    result = result.split(secret).join(REDACTED);
  }
  return result;
}

/**
 * 一時的にクレデンシャルを注入してコマンドを実行
 */
export function injectForCommand(
  credName: string,
  credValue: string,
  command: string,
): { stdout: string; stderr: string; exitCode: number } {
  const env = { ...process.env, [credName]: credValue };

  try {
    const stdout = execSync(command, {
      env,
      encoding: "utf-8",
      timeout: COMMAND_TIMEOUT_MS,
    });
    return { stdout: redactSecret(stdout, credValue), stderr: "", exitCode: 0 };
  } catch (err: any) {
    return {
      stdout: redactSecret(err.stdout ?? "", credValue),
      stderr: redactSecret(err.stderr ?? err.message, credValue),
      exitCode: err.status ?? 1,
    };
  }
}

/**
 * Vaultから特定のクレデンシャル値を取得（注入用）
 */
export function retrieveCredential(varName: string, pathOverrides?: Partial<VaultPaths>): string | null {
  const paths = resolvePaths(pathOverrides);
  const vaultPath = join(paths.vaultDir, `env_${varName}.enc`);
  if (!existsSync(vaultPath)) return null;
  return decrypt(readFileSync(vaultPath, "utf-8"), paths.vaultKeyPath);
}

export function getVaultState(pathOverrides?: Partial<VaultPaths>): VaultState | null {
  const paths = resolvePaths(pathOverrides);
  return loadState(paths.statePath);
}
