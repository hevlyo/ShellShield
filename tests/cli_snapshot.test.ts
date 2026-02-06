import { describe, expect, test, beforeAll } from "bun:test";
import { spawn } from "bun";
import { join } from "node:path";

const PROJECT_ROOT = join(import.meta.dir, "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "index.ts");
const BUN_PATH = process.execPath;
let canUseScript = false;

beforeAll(async () => {
  try {
    const probe = spawn({
      cmd: ["script", "-q", "-c", "echo ok", "/dev/null"],
      stdin: "ignore",
      stderr: "ignore",
      stdout: "ignore",
      cwd: PROJECT_ROOT,
    });
    const exitCode = await probe.exited;
    canUseScript = exitCode === 0;
  } catch {
    canUseScript = false;
  }
});

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

async function runCheck(command: string, env: Record<string, string> = {}, stdin?: string) {
  const proc = spawn({
    cmd: [BUN_PATH, "run", CLI_PATH, "--check", command],
    stdin: stdin ? "pipe" : "ignore",
    stderr: "pipe",
    stdout: "ignore",
    env: { ...process.env, BUN_COVERAGE: "0", SHELLSHIELD_AUDIT_DISABLED: "1", ...env },
    cwd: PROJECT_ROOT,
  });
  if (stdin && proc.stdin) {
    proc.stdin.write(stdin);
    proc.stdin.end();
  }
  const exitCode = await proc.exited;
  const stderr = await readStream(proc.stderr);
  return { exitCode, stderr };
}

async function runCheckTty(command: string, env: Record<string, string>, stdin: string) {
  const fullCmd = `${BUN_PATH} run "${CLI_PATH}" --check "${command.replaceAll('"', '\\"')}"`;
  const proc = spawn({
    cmd: ["script", "-q", "-c", fullCmd, "/dev/null"],
    stdin: "pipe",
    stderr: "pipe",
    stdout: "pipe",
    env: { ...process.env, BUN_COVERAGE: "0", SHELLSHIELD_AUDIT_DISABLED: "1", ...env },
    cwd: PROJECT_ROOT,
  });
  proc.stdin.write(stdin);
  proc.stdin.end();
  const exitCode = await proc.exited;
  const stderr = await readStream(proc.stderr);
  const stdout = await readStream(proc.stdout);
  return { exitCode, output: stdout + stderr };
}

describe("CLI output snapshots", () => {
  test("blocked message (enforce)", async () => {
    const { exitCode, stderr } = await runCheck("rm -rf /tmp/test", { SHELLSHIELD_MODE: "enforce" });
    expect(exitCode).toBe(2);
    expect(stderr).toMatchSnapshot();
  });

  test("permissive warning", async () => {
    const { exitCode, stderr } = await runCheck("rm -rf /tmp/test", { SHELLSHIELD_MODE: "permissive" });
    expect(exitCode).toBe(0);
    expect(stderr).toMatchSnapshot();
  });

  test("interactive approve/cancel messaging", async () => {
    if (!canUseScript) return;
    const denied = await runCheckTty("rm -rf /tmp/test", { SHELLSHIELD_MODE: "interactive" }, "n\n");
    expect(denied.output).toContain("ShellShield");
    expect(denied.output).toMatchSnapshot();

    const approved = await runCheckTty("rm -rf /tmp/test", { SHELLSHIELD_MODE: "interactive" }, "y\n");
    expect(approved.output).toContain("Approved. Command will execute");
    expect(approved.output).toMatchSnapshot();
  });
});
