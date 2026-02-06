import { describe, expect, test } from "bun:test";
import { spawn } from "bun";
import { join, resolve } from "node:path";

const PROJECT_ROOT = resolve(import.meta.dir, "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "index.ts");
const BUN_PATH = process.execPath;

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
  } finally {
    reader.releaseLock();
  }
}

async function runCheck(command: string, env: Record<string, string>) {
  const proc = spawn({
    cmd: [BUN_PATH, "run", CLI_PATH, "--check", command],
    stdin: "ignore",
    stderr: "pipe",
    stdout: "ignore",
    env: { ...process.env, BUN_COVERAGE: "0", SHELLSHIELD_AUDIT_DISABLED: "1", ...env },
    cwd: PROJECT_ROOT,
  });
  const exitCode = await proc.exited;
  const stderr = await readStream(proc.stderr);
  return { exitCode, stderr };
}

describe("Permissive Mode", () => {
  test("does not block when mode=permissive", async () => {
    const { exitCode, stderr } = await runCheck("rm /etc/passwd", { SHELLSHIELD_MODE: "permissive" });
    expect(exitCode).toBe(0);
    expect(stderr).toContain("ShellShield WARNING");
    expect(stderr).toContain("would be blocked");
  });

  test("blocks when mode=enforce", async () => {
    const { exitCode, stderr } = await runCheck("rm /etc/passwd", { SHELLSHIELD_MODE: "enforce" });
    expect(exitCode).toBe(2);
    expect(stderr).toContain("ShellShield BLOCKED");
  });
});
