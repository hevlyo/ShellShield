import { describe, expect, test } from "bun:test";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { checkDestructive } from "../src/parser/analyzer";
import { DEFAULT_BLOCKED, DEFAULT_TRUSTED_DOMAINS } from "../src/constants";

const TEST_CONTEXT = {
  blocked: new Set(DEFAULT_BLOCKED),
  allowed: new Set<string>(),
  trustedDomains: DEFAULT_TRUSTED_DOMAINS,
  threshold: 50,
  mode: "enforce" as const,
  customRules: [],
  maxSubshellDepth: 5,
};

function analyze(command: string) {
  return checkDestructive(command, 0, TEST_CONTEXT);
}

describe("Shell context snapshot (aliases/functions)", () => {
  test("blocks when safe command is aliased to blocked primitive", () => {
    const prev = process.env.SHELLSHIELD_CONTEXT_PATH;
    let dir = "";
    try {
      dir = mkdtempSync(join(tmpdir(), "shellshield-shell-context-"));
      const p = join(dir, "snapshot.json");
      writeFileSync(
        p,
        JSON.stringify(
          {
            version: 1,
            generatedAt: new Date().toISOString(),
            entries: {
              ls: {
                kind: "alias",
                output: "ls is aliased to 'rm -rf /'",
                expansion: "rm -rf /",
              },
            },
          },
          null,
          2
        ) + "\n",
        "utf8"
      );

      process.env.SHELLSHIELD_CONTEXT_PATH = p;
      const result = analyze("ls /tmp");
      expect(result.blocked).toBe(true);
      if (result.blocked) {
        expect(result.reason).toContain("SHELL CONTEXT OVERRIDE");
      }
    } finally {
      if (prev === undefined) delete process.env.SHELLSHIELD_CONTEXT_PATH;
      else process.env.SHELLSHIELD_CONTEXT_PATH = prev;

      if (dir) {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          // best-effort cleanup
        }
      }
    }
  });

  test("does not block benign aliases", () => {
    const prev = process.env.SHELLSHIELD_CONTEXT_PATH;
    let dir = "";
    try {
      dir = mkdtempSync(join(tmpdir(), "shellshield-shell-context-"));
      const p = join(dir, "snapshot-benign.json");
      writeFileSync(
        p,
        JSON.stringify(
          {
            version: 1,
            generatedAt: new Date().toISOString(),
            entries: {
              ls: {
                kind: "alias",
                output: "ls is aliased to 'ls --color=auto'",
                expansion: "ls --color=auto",
              },
            },
          },
          null,
          2
        ) + "\n",
        "utf8"
      );

      process.env.SHELLSHIELD_CONTEXT_PATH = p;
      const result = analyze("ls /tmp");
      expect(result.blocked).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.SHELLSHIELD_CONTEXT_PATH;
      else process.env.SHELLSHIELD_CONTEXT_PATH = prev;

      if (dir) {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          // best-effort cleanup
        }
      }
    }
  });
});
