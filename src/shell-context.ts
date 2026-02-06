import { existsSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";

export type ShellContextKind =
  | "alias"
  | "function"
  | "builtin"
  | "keyword"
  | "file"
  | "unknown";

export interface ShellContextEntry {
  kind: ShellContextKind;
  output: string;
  expansion?: string;
}

export interface ShellContextSnapshot {
  version: 1;
  generatedAt: string;
  shell?: string;
  entries: Record<string, ShellContextEntry>;
}

let cache: { path: string; snapshot: ShellContextSnapshot | null } | null = null;

function normalizeCmd(cmd: string): string {
  return cmd.trim().toLowerCase();
}

function defaultSnapshotPath(): string {
  return resolve(homedir(), ".shellshield", "shell-context.json");
}

export function getShellContextSnapshotPath(): string | null {
  const raw = process.env.SHELLSHIELD_CONTEXT_PATH;
  if (raw && raw.trim().length > 0) return raw.trim();
  return null;
}

export function readShellContextSnapshot(path?: string): ShellContextSnapshot | null {
  const p = path ?? defaultSnapshotPath();
  if (cache && cache.path === p) return cache.snapshot;

  try {
    if (!existsSync(p)) {
      cache = { path: p, snapshot: null };
      return null;
    }
    const raw = JSON.parse(readFileSync(p, "utf8")) as ShellContextSnapshot;
    if (!raw || raw.version !== 1 || typeof raw.entries !== "object") {
      cache = { path: p, snapshot: null };
      return null;
    }
    cache = { path: p, snapshot: raw };
    return raw;
  } catch {
    cache = { path: p, snapshot: null };
    return null;
  }
}

export function writeShellContextSnapshot(path: string, snapshot: ShellContextSnapshot): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
  cache = { path, snapshot };
}

export function parseTypeOutput(output: string): ShellContextEntry {
  const out = output.trim();
  const first = out.split("\n")[0] ?? "";

  // bash: "ls is aliased to 'ls --color=auto'"
  const aliasedTo = first.match(/\bis aliased to\s+(['`\"])([\s\S]*?)\1/);
  if (aliasedTo) {
    return { kind: "alias", output: out, expansion: aliasedTo[2] };
  }

  // zsh: "ls is an alias for ls -G" (sometimes quoted)
  const aliasForQuoted = first.match(/\bis an alias for\s+(['`\"])([\s\S]*?)\1/);
  if (aliasForQuoted) {
    return { kind: "alias", output: out, expansion: aliasForQuoted[2] };
  }
  const aliasFor = first.match(/\bis an alias for\s+(.+)$/);
  if (aliasFor) {
    return { kind: "alias", output: out, expansion: aliasFor[1].trim() };
  }

  // bash/zsh: function output + body
  if (first.includes(" is a function") || first.includes(" is a shell function")) {
    return { kind: "function", output: out };
  }

  // builtins
  if (first.includes(" is a shell builtin") || first.includes(" is a builtin")) {
    return { kind: "builtin", output: out };
  }

  // keywords
  if (first.includes(" is a shell keyword") || first.includes(" is a reserved word")) {
    return { kind: "keyword", output: out };
  }

  // file paths
  if (/\bis\s+\//.test(first)) {
    return { kind: "file", output: out };
  }

  // hashed path (zsh)
  if (/\bis hashed\s*\(\//.test(first)) return { kind: "file", output: out };

  return { kind: "unknown", output: out };
}
export function getShellContextEntry(cmd: string): ShellContextEntry | null {
  const p = getShellContextSnapshotPath();
  if (!p) return null;
  const snap = readShellContextSnapshot(p);
  if (!snap) return null;
  const key = normalizeCmd(cmd);
  return snap.entries[key] ?? null;
}

function escapeRegExp(s: string): string {
  return s.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
}

export function findBlockedTokenInShellContext(
  entry: ShellContextEntry,
  blocked: Set<string>
): string | null {
  const haystack = `${entry.expansion ?? ""}\n${entry.output}`;
  for (const b of blocked) {
    const re = new RegExp(`\\b${escapeRegExp(b)}\\b`, "i");
    if (re.test(haystack)) return b;
  }
  return null;
}
