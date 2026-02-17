import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PROJECT_ROOT = join(import.meta.dir, "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "index.ts");
const BUN_PATH = process.execPath;

function runCli(args: string[], homeDir: string) {
  const proc = Bun.spawnSync({
    cmd: [BUN_PATH, "run", CLI_PATH, ...args],
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      BUN_COVERAGE: "0",
      HOME: homeDir,
      INIT_CWD: PROJECT_ROOT,
      PWD: PROJECT_ROOT,
      SHELLSHIELD_AUDIT_DISABLED: "0",
    },
  });

  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout?.toString() ?? "",
    stderr: proc.stderr?.toString() ?? "",
  };
}

describe("Run and Receipt CLI", () => {
  test("run validates required url argument", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-run-"));
    try {
      const result = runCli(["--run"], tempHome);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain("Usage: shellshield --run <url>");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("run supports dry-run for a data URL", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-run-"));
    try {
      const result = runCli(["--run", "data:text/plain,echo%20hello", "--dry-run"], tempHome);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("ShellShield Remote Run");
      expect(result.stdout).toContain("Dry run complete. Script was not executed.");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("receipt shows latest run entry", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-run-"));
    try {
      const runResult = runCli(["--run", "data:text/plain,echo%20hello", "--dry-run"], tempHome);
      expect(runResult.exitCode).toBe(0);

      const receipt = runCli(["--receipt"], tempHome);
      expect(receipt.exitCode).toBe(0);
      expect(receipt.stdout).toContain("ShellShield Receipt");
      expect(receipt.stdout).toContain("URL: data:text/plain,echo%20hello");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("receipt warns when no run receipts exist", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-run-"));
    try {
      const result = runCli(["--receipt"], tempHome);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("No audit log found");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });
});
