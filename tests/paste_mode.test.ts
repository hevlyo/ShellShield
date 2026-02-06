import { describe, expect, test } from "bun:test";
import { spawn } from "bun";
import { join } from "node:path";

const PROJECT_ROOT = join(import.meta.dir, "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "index.ts");
const BUN_PATH = process.execPath;

async function runPaste(input: string, env: Record<string, string> = {}) {
  const proc = spawn({
    cmd: [BUN_PATH, "run", CLI_PATH, "--paste"],
    stdin: new Blob([input]),
    stderr: "pipe",
    stdout: "pipe",
    env: {
      ...process.env,
      BUN_COVERAGE: "0",
      SHELLSHIELD_AUDIT_DISABLED: "1",
      SHELLSHIELD_MODE: "enforce",
      ...env,
    },
    cwd: PROJECT_ROOT,
  });
  const exitCode = await proc.exited;
  const stderr = (await proc.stderr?.text()) ?? "";
  return { exitCode, stderr };
}

describe("Paste mode", () => {
  test("blocks when any pasted line is dangerous", async () => {
    const { exitCode, stderr } = await runPaste("echo ok\nrm -rf /tmp/test\n");
    expect(exitCode).toBe(2);
    expect(stderr).toContain("Destructive");
  });

  test("allows benign multi-line paste", async () => {
    const { exitCode } = await runPaste("echo ok\nls -la\n");
    expect(exitCode).toBe(0);
  });
});
