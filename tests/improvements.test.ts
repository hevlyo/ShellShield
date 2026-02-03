import { describe, test, expect } from "bun:test";
import { spawn } from "bun";
import { join } from "path";

const HOOK_PATH = join(import.meta.dir, "..", "src", "index.ts");

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
  command: string
): Promise<{ exitCode: number; stderr: string }> {
  const input = JSON.stringify({ tool_input: { command } });

  const proc = spawn({
    cmd: ["bun", "run", HOOK_PATH],
    stdin: "pipe",
    stderr: "pipe",
    stdout: "pipe",
  });

  if (proc.stdin) {
    proc.stdin.write(input);
    proc.stdin.end();
  }

  const exitCode = await proc.exited;
  const stderr = await readStream(proc.stderr);

  return { exitCode, stderr };
}

describe("New bypasses that SHOULD be blocked", () => {
  test("CMD=rm; $CMD file (variable expansion)", async () => {
    const { exitCode } = await runHook("CMD=rm; $CMD file");
    expect(exitCode).toBe(2);
  });

  test("sh -c 'sh -c \"rm file\"' (nested subshell)", async () => {
    const { exitCode } = await runHook("sh -c 'sh -c \"rm file\"'");
    expect(exitCode).toBe(2);
  });

  test("deeply nested subshells (4 levels)", async () => {
    const command = "sh -c sh -c sh -c sh -c rm file";
    const { exitCode } = await runHook(command);
    expect(exitCode).toBe(2);
  });

  test("wipe file.txt", async () => {
    const { exitCode } = await runHook("wipe file.txt");
    expect(exitCode).toBe(2);
  });

  test("srm file.txt", async () => {
    const { exitCode } = await runHook("srm file.txt");
    expect(exitCode).toBe(2);
  });

  test("RM -rf dir (case insensitivity)", async () => {
     const { exitCode } = await runHook("RM -rf dir");
     expect(exitCode).toBe(2);
  });

  test("dd if=/dev/zero of=file.txt (destructive dd)", async () => {
    const { exitCode } = await runHook("dd if=/dev/zero of=important_file");
    expect(exitCode).toBe(2);
  });
});

describe("Improved UX", () => {
  test("suggests trash command for rm", async () => {
    const { stderr } = await runHook("rm file.txt");
    expect(stderr).toContain("trash file.txt");
  });

  test("suggests trash command for rm -rf", async () => {
    const { stderr } = await runHook("rm -rf folder/");
    expect(stderr).toContain("trash folder/");
  });
});

describe("Configuration", () => {
  test("allows custom blocked commands via env", async () => {
    const input = JSON.stringify({ tool_input: { command: "custom-delete file" } });
    const proc = spawn({
      cmd: ["bun", "run", HOOK_PATH],
      stdin: "pipe",
      stderr: "pipe",
      stdout: "pipe",
      env: { ...process.env, OPENCODE_BLOCK_COMMANDS: "custom-delete,another-one" }
    });

    proc.stdin.write(input);
    proc.stdin.end();

    const exitCode = await proc.exited;
    expect(exitCode).toBe(2);
  });

  test("allows custom allowed commands via env", async () => {
    const input = JSON.stringify({ tool_input: { command: "rm safe-file" } });
    const proc = spawn({
      cmd: ["bun", "run", HOOK_PATH],
      stdin: "pipe",
      stderr: "pipe",
      stdout: "pipe",
      env: { ...process.env, OPENCODE_ALLOW_COMMANDS: "rm" }
    });

    proc.stdin.write(input);
    proc.stdin.end();

    const exitCode = await proc.exited;
    expect(exitCode).toBe(0);
  });
});
