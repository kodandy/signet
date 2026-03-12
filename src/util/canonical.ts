/**
 * 再帰的にキーをソートした安定なJSON文字列を生成（正規化）。
 * 署名・ハッシュ計算の入力として使用し、キー挿入順序に依存しない
 * 決定的なシリアライズを保証する。
 */
export function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, (_, value) => {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  });
}
