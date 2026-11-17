import { existsSync, readFileSync, renameSync, writeFileSync, chmodSync, copyFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Repo root (packages/common/src -> ../../..). */
export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
export const ENV_PATH = join(REPO_ROOT, ".env");
export const ENV_EXAMPLE_PATH = join(REPO_ROOT, ".env.example");

const LINE = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/;

/** Parse a .env file into key/value pairs. Values are taken verbatim (no quotes or escapes). */
export function readEnvFile(path: string = ENV_PATH): Record<string, string> {
  if (!existsSync(path)) return {};
  const out: Record<string, string> = {};
  for (const raw of readFileSync(path, "utf8").split(/\r?\n/)) {
    if (raw.trimStart().startsWith("#")) continue;
    const m = LINE.exec(raw);
    if (m) out[m[1]!] = unquote(m[2]!);
  }
  return out;
}

/** Strip one pair of matching surrounding quotes, as dotenv does. */
function unquote(value: string): string {
  const v = value.trim();
  return v.length >= 2 && (v[0] === '"' || v[0] === "'") && v.at(-1) === v[0] ? v.slice(1, -1) : v;
}

/** process.env overlaid on the repo .env (process.env wins). */
export function loadEnv(): Record<string, string | undefined> {
  return { ...readEnvFile(), ...process.env };
}

/** Create .env from .env.example if it does not exist yet. Returns true if created. */
export function ensureEnvFile(): boolean {
  if (existsSync(ENV_PATH)) return false;
  copyFileSync(ENV_EXAMPLE_PATH, ENV_PATH);
  chmodSync(ENV_PATH, 0o600);
  return true;
}

/**
 * Fill keys that are missing or empty in .env. Never overwrites a non-empty value.
 * Rewrites atomically and keeps the file private (0600). Returns the keys it filled.
 */
export function fillEnvValues(values: Record<string, string>, path: string = ENV_PATH): string[] {
  const lines = existsSync(path) ? readFileSync(path, "utf8").split(/\r?\n/) : [];
  const filled: string[] = [];
  const seen = new Set<string>();
  const next = lines.map((raw) => {
    const m = LINE.exec(raw);
    if (!m || raw.trimStart().startsWith("#")) return raw;
    const key = m[1]!;
    seen.add(key);
    if (key in values && m[2] === "") {
      filled.push(key);
      return `${key}=${values[key]}`;
    }
    return raw;
  });
  for (const [key, value] of Object.entries(values)) {
    if (!seen.has(key)) {
      next.push(`${key}=${value}`);
      filled.push(key);
    }
  }
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, next.join("\n").replace(/\n*$/, "\n"), { mode: 0o600 });
  renameSync(tmp, path);
  chmodSync(path, 0o600);
  return filled;
}
