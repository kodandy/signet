import { buildSync } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";

// 1. esbuild bundle
buildSync({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  outfile: "dist/index.js",
  external: ["better-sqlite3", "tweetnacl", "commander", "yaml"],
});

// 2. Prepend shebang
const content = readFileSync("dist/index.js", "utf-8");
writeFileSync("dist/index.js", "#!/usr/bin/env node\n" + content);

// 3. Type declarations
execSync("./node_modules/.bin/tsc --emitDeclarationOnly", { stdio: "inherit" });

console.log("Build complete.");
