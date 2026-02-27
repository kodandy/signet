import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { execSync } from "node:child_process";
import { createHash, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

const VAULT_DIR = join(homedir(), ".signet", "vault");
const VAULT_KEY_PATH = join(homedir(), ".signet", "vault.key");

export interface VaultConfig {
  envFiles?: string[];             // 退避する.envファイルパス (デフォルト: [".env"])
  credentialEnvVars?: string[];    // 退避する環境変数名
  projectDir?: string;             // プロジェクトルート (デフォルト: cwd)
}

export interface VaultState {
  active: boolean;
  evacuatedFiles: string[];
  evacuatedVars: string[];
  projectDir: string;
}

const STATE_PATH = join(homedir(), ".signet", "vault-state.json");

function getVaultKey(): Buffer {
  if (!existsSync(VAULT_KEY_PATH)) {
    const dir = join(VAULT_KEY_PATH, "..");
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const key = randomBytes(32);
    writeFileSync(VAULT_KEY_PATH, key, { mode: 0o600 });
    return key;
  }
  return readFileSync(VAULT_KEY_PATH);
}

function encrypt(data: string): string {
  const key = getVaultKey();
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(data, "utf-8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(data: string): string {
  const key = getVaultKey();
  const [ivHex, encrypted] = data.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}

function loadState(): VaultState | null {
  if (!existsSync(STATE_PATH)) return null;
  return JSON.parse(readFileSync(STATE_PATH, "utf-8")) as VaultState;
}

function saveState(state: VaultState): void {
  const dir = join(STATE_PATH, "..");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  writeFileSync(STATE_PATH, JSON.stringify(state, null, 2), { mode: 0o600 });
}

function clearState(): void {
  if (existsSync(STATE_PATH)) unlinkSync(STATE_PATH);
}

/**
 * Vault有効化: .envファイルを退避、環境変数をクリア
 */
export function activate(config: VaultConfig = {}): VaultState {
  const existing = loadState();
  if (existing?.active) {
    throw new Error("Vault is already active. Run deactivate first.");
  }

  const projectDir = resolve(config.projectDir ?? process.cwd());
  const envFiles = config.envFiles ?? [".env"];
  const evacuatedFiles: string[] = [];
  const evacuatedVars: string[] = [];

  if (!existsSync(VAULT_DIR)) {
    mkdirSync(VAULT_DIR, { recursive: true, mode: 0o700 });
  }

  // 1. .envファイルを暗号化して退避
  for (const envFile of envFiles) {
    const fullPath = resolve(projectDir, envFile);
    if (existsSync(fullPath)) {
      const content = readFileSync(fullPath, "utf-8");
      const hash = createHash("sha256").update(fullPath).digest("hex").slice(0, 16);
      const vaultPath = join(VAULT_DIR, `${hash}.enc`);

      writeFileSync(vaultPath, encrypt(content), { mode: 0o600 });
      // 元ファイルのバックアップパス情報を保存
      writeFileSync(vaultPath + ".meta", JSON.stringify({ originalPath: fullPath }), { mode: 0o600 });
      unlinkSync(fullPath);
      evacuatedFiles.push(fullPath);
    }
  }

  // 2. 指定された環境変数を退避
  if (config.credentialEnvVars) {
    for (const varName of config.credentialEnvVars) {
      if (process.env[varName] !== undefined) {
        const vaultPath = join(VAULT_DIR, `env_${varName}.enc`);
        writeFileSync(vaultPath, encrypt(process.env[varName]!), { mode: 0o600 });
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

  saveState(state);
  return state;
}

/**
 * Vault無効化: 退避したファイルと環境変数を復元
 */
export function deactivate(): VaultState {
  const state = loadState();
  if (!state?.active) {
    throw new Error("Vault is not active.");
  }

  // 1. .envファイルを復元
  for (const filePath of state.evacuatedFiles) {
    const hash = createHash("sha256").update(filePath).digest("hex").slice(0, 16);
    const vaultPath = join(VAULT_DIR, `${hash}.enc`);

    if (existsSync(vaultPath)) {
      const content = decrypt(readFileSync(vaultPath, "utf-8"));
      writeFileSync(filePath, content, { mode: 0o600 });
      unlinkSync(vaultPath);
      const metaPath = vaultPath + ".meta";
      if (existsSync(metaPath)) unlinkSync(metaPath);
    }
  }

  // 2. 環境変数を復元
  for (const varName of state.evacuatedVars) {
    const vaultPath = join(VAULT_DIR, `env_${varName}.enc`);
    if (existsSync(vaultPath)) {
      const value = decrypt(readFileSync(vaultPath, "utf-8"));
      process.env[varName] = value;
      unlinkSync(vaultPath);
    }
  }

  clearState();

  return { ...state, active: false };
}

/**
 * 一時的にクレデンシャルを注入してコマンドを実行
 */
export function injectForCommand(
  credName: string,
  credValue: string,
  command: string,
): { stdout: string; stderr: string; exitCode: number } {
  // クレデンシャルを一時的に環境変数に設定してコマンド実行
  const env = { ...process.env, [credName]: credValue };

  try {
    const stdout = execSync(command, {
      env,
      encoding: "utf-8",
      timeout: 30000,
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err: any) {
    return {
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? err.message,
      exitCode: err.status ?? 1,
    };
  }
}

/**
 * Vaultから特定のクレデンシャル値を取得（注入用）
 */
export function retrieveCredential(varName: string): string | null {
  const vaultPath = join(VAULT_DIR, `env_${varName}.enc`);
  if (!existsSync(vaultPath)) return null;
  return decrypt(readFileSync(vaultPath, "utf-8"));
}

export function getVaultState(): VaultState | null {
  return loadState();
}
