import { describe, expect, test } from "bun:test";
import { spawn } from "bun";
import { join } from "node:path";

const PROJECT_ROOT = join(import.meta.dir, "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "index.ts");
const BUN_PATH = process.execPath;

async function runScore(url: string) {
  const proc = spawn({
    cmd: [BUN_PATH, "run", CLI_PATH, "--score", url, "--json"],
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, BUN_COVERAGE: "0" },
    cwd: PROJECT_ROOT,
  });
  const exitCode = await proc.exited;
  const stdout = (await proc.stdout?.text()) ?? "";
  return { exitCode, stdout };
}

describe("CLI URL score", () => {
  test("returns json", async () => {
    const { exitCode, stdout } = await runScore("https://github.com/openai");
    expect(exitCode).toBe(0);
    const data = JSON.parse(stdout.trim());
    expect(typeof data.score).toBe("number");
    expect(Array.isArray(data.reasons)).toBe(true);
  });
});
