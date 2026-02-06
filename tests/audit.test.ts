import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { logAudit } from "../src/audit";

describe("audit telemetry", () => {
  test("writes structured entry with decision + rule", () => {
    const prevPath = process.env.SHELLSHIELD_AUDIT_PATH;
    const prevDir = process.env.SHELLSHIELD_AUDIT_DIR;

    const dir = mkdtempSync(join(tmpdir(), "shellshield-audit-"));
    const logPath = join(dir, "audit.log");

    try {
      process.env.SHELLSHIELD_AUDIT_PATH = logPath;
      process.env.SHELLSHIELD_AUDIT_DIR = dir;

      logAudit(
        "rm -rf /",
        {
          blocked: true,
          reason: "CRITICAL PATH PROTECTED",
          suggestion: "Do not delete /",
          rule: "CoreAstRule",
        },
        { decision: "blocked", mode: "enforce", threshold: 50, source: "stdin" }
      );

      const raw = readFileSync(logPath, "utf8").trim();
      const entry = JSON.parse(raw);

      expect(entry.v).toBe(1);
      expect(entry.blocked).toBe(true);
      expect(entry.decision).toBe("blocked");
      expect(entry.rule).toBe("CoreAstRule");
      expect(entry.reason).toBe("CRITICAL PATH PROTECTED");
      expect(entry.source).toBe("stdin");
    } finally {
      if (prevPath === undefined) delete process.env.SHELLSHIELD_AUDIT_PATH;
      else process.env.SHELLSHIELD_AUDIT_PATH = prevPath;

      if (prevDir === undefined) delete process.env.SHELLSHIELD_AUDIT_DIR;
      else process.env.SHELLSHIELD_AUDIT_DIR = prevDir;

      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    }
  });
});
