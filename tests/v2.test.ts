import { describe, test, expect } from "bun:test";
import { spawn } from "bun";
import { join } from "node:path";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { execSync } from "node:child_process";
import { checkDestructive } from "../src/parser/analyzer";
import { DEFAULT_BLOCKED, DEFAULT_TRUSTED_DOMAINS } from "../src/constants";

const PROJECT_ROOT = join(import.meta.dir, "..");
const HOOK_PATH = join(PROJECT_ROOT, "src", "index.ts");
const BUN_PATH = process.execPath;
const TEST_DIR = join(import.meta.dir, "tmp-v2-tests");

const TEST_CONTEXT = {
  blocked: new Set(DEFAULT_BLOCKED),
  allowed: new Set<string>(),
  trustedDomains: DEFAULT_TRUSTED_DOMAINS,
  threshold: 50,
  mode: "enforce" as const,
  customRules: [],
  maxSubshellDepth: 5,
};

function analyze(command: string) {
  return checkDestructive(command, 0, TEST_CONTEXT);
}

function setupTestDir() {
  if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
  mkdirSync(TEST_DIR, { recursive: true });
}

async function readStream(stream?: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!stream) return "";
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let result = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) result += decoder.decode(value, { stream: true });
    }
    result += decoder.decode();
    return result;
  } catch {
    return result;
  } finally {
    reader.releaseLock();
  }
}

async function runHook(
  command: string,
  env: Record<string, string> = {}
): Promise<{ exitCode: number; stderr: string }> {
  const input = JSON.stringify({ tool_input: { command } });

  const proc = spawn({
    cmd: [BUN_PATH, "run", HOOK_PATH],
    stdin: "pipe",
    stderr: "pipe",
    stdout: "ignore",
    env: { ...process.env, SHELLSHIELD_MODE: "enforce", ...env },
    cwd: PROJECT_ROOT,
  });

  if (proc.stdin) {
    proc.stdin.write(input);
    proc.stdin.end();
  }

  const exitCode = await proc.exited;
  const stderr = await readStream(proc.stderr);

  return { exitCode, stderr };
}

describe("ShellShield v2.0 - Protected Paths", () => {
  test("blocks deleting root /", () => {
    const result = analyze("rm -rf /");
    expect(result.blocked).toBe(true);
    if (result.blocked) {
      expect(result.reason).toContain("CRITICAL PATH PROTECTED");
    }
  });

  test("blocks deleting /etc", () => {
    const result = analyze("rm -rf /etc");
    expect(result.blocked).toBe(true);
    if (result.blocked) {
      expect(result.reason).toContain("CRITICAL PATH PROTECTED");
    }
  });

  test("blocks deleting .git folder", async () => {
    const result = analyze("rm -rf .git");
    expect(result.blocked).toBe(true);
    if (result.blocked) {
      expect(result.reason).toContain("PROTECTED");
    }
  });
});

describe("ShellShield v2.0 - Git Safety", () => {
    test("warns if deleting a file with uncommitted changes", async () => {
        setupTestDir();
        const repoPath = join(TEST_DIR, "git-repo");
        mkdirSync(repoPath, { recursive: true });
        execSync("git init", { cwd: repoPath });
        writeFileSync(join(repoPath, "file.txt"), "hello");
        execSync("git add file.txt", { cwd: repoPath });
        execSync("git commit -m 'initial'", {
          cwd: repoPath,
          env: {
            ...process.env,
            GIT_AUTHOR_NAME: "shellshield",
            GIT_AUTHOR_EMAIL: "shellshield@example.com",
            GIT_COMMITTER_NAME: "shellshield",
            GIT_COMMITTER_EMAIL: "shellshield@example.com",
          },
        });
        writeFileSync(join(repoPath, "file.txt"), "hello world"); 

        const result = analyze(`rm ${join(repoPath, "file.txt")}`);
        expect(result.blocked).toBe(true);
        if (result.blocked) {
          expect(result.reason).toContain("UNCOMMITTED CHANGES DETECTED");
        }
    });
});

describe("ShellShield v2.0 - Threshold Protection", () => {
    test("blocks if too many files are targeted (e.g. > 50)", () => {
        const manyFiles = Array.from({ length: 60 }, (_, i) => `file${i}.txt`).join(" ");
        const result = analyze(`rm ${manyFiles}`);
        expect(result.blocked).toBe(true);
        if (result.blocked) {
          expect(result.reason).toContain("VOLUME THRESHOLD EXCEEDED");
        }
    });

    test("respects SHELLSHIELD_THRESHOLD env var", () => {
        const manyFiles = Array.from({ length: 6 }, (_, i) => `file${i}.txt`).join(" ");
        const result = checkDestructive(`rm ${manyFiles}`, 0, { ...TEST_CONTEXT, threshold: 5 });
        expect(result.blocked).toBe(true);
        if (result.blocked) {
          expect(result.reason).toContain("VOLUME THRESHOLD EXCEEDED");
        }
    });
});
