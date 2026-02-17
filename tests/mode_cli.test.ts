import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
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
      SHELLSHIELD_AUDIT_DISABLED: "1",
    },
  });

  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout?.toString() ?? "",
    stderr: proc.stderr?.toString() ?? "",
  };
}

describe("Mode selection CLI", () => {
  test("shows default mode when no config exists", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-mode-"));
    try {
      const result = runCli(["--mode"], tempHome);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Current mode: enforce");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("sets and persists selected mode", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-mode-"));
    try {
      const setResult = runCli(["--mode", "permissive"], tempHome);
      expect(setResult.exitCode).toBe(0);
      expect(setResult.stdout).toContain("Mode updated: permissive");

      const configPath = join(tempHome, ".shellshield.json");
      const parsed = JSON.parse(readFileSync(configPath, "utf8")) as { mode?: string };
      expect(parsed.mode).toBe("permissive");

      const showResult = runCli(["--mode"], tempHome);
      expect(showResult.exitCode).toBe(0);
      expect(showResult.stdout).toContain("Current mode: permissive");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("rejects invalid mode values", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-mode-"));
    try {
      const result = runCli(["--mode", "unsafe"], tempHome);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain("Invalid mode");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("select-mode requires TTY", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-mode-"));
    try {
      const result = runCli(["--select-mode"], tempHome);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain("requires an interactive TTY");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });
});
