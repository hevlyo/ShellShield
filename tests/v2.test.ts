import { describe, test, expect } from "bun:test";
import { spawn } from "bun";
import { join } from "path";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "fs";
import { execSync } from "child_process";

const PROJECT_ROOT = join(import.meta.dir, "..");
const HOOK_PATH = join(PROJECT_ROOT, "src", "index.ts");
const TEST_DIR = join(import.meta.dir, "tmp-v2-tests");

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
    cmd: ["/home/hevlyo/.bun/bin/bun", "run", HOOK_PATH],
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
  test("blocks deleting root /", async () => {
    const { exitCode, stderr } = await runHook("rm -rf /");
    expect(exitCode).toBe(2);
    expect(stderr).toContain("CRITICAL PATH PROTECTED");
  });

  test("blocks deleting /etc", async () => {
    const { exitCode, stderr } = await runHook("rm -rf /etc");
    expect(exitCode).toBe(2);
    expect(stderr).toContain("CRITICAL PATH PROTECTED");
  });

  test("blocks deleting .git folder", async () => {
    const { exitCode, stderr } = await runHook("rm -rf .git");
    expect(exitCode).toBe(2);
    expect(stderr).toContain("PROTECTED");
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

        const { exitCode, stderr } = await runHook(`rm ${join(repoPath, "file.txt")}`);
        expect(exitCode).toBe(2);
        expect(stderr).toContain("UNCOMMITTED CHANGES DETECTED");
    });
});

describe("ShellShield v2.0 - Threshold Protection", () => {
    test("blocks if too many files are targeted (e.g. > 50)", async () => {
        const manyFiles = Array.from({ length: 60 }, (_, i) => `file${i}.txt`).join(" ");
        const { exitCode, stderr } = await runHook(`rm ${manyFiles}`);
        expect(exitCode).toBe(2);
        expect(stderr).toContain("VOLUME THRESHOLD EXCEEDED");
    });

    test("respects SHELLSHIELD_THRESHOLD env var", async () => {
        const manyFiles = Array.from({ length: 6 }, (_, i) => `file${i}.txt`).join(" ");
        const { exitCode, stderr } = await runHook(`rm ${manyFiles}`, {
            SHELLSHIELD_THRESHOLD: "5"
        });
        expect(exitCode).toBe(2);
        expect(stderr).toContain("VOLUME THRESHOLD EXCEEDED");
    });
});
