import { describe, expect, test } from "bun:test";
import { checkDestructive } from "../src/parser/analyzer";
import { DEFAULT_BLOCKED, DEFAULT_TRUSTED_DOMAINS } from "../src/constants";

const TEST_CONTEXT = {
  blocked: new Set(DEFAULT_BLOCKED),
  allowed: new Set<string>(),
  trustedDomains: DEFAULT_TRUSTED_DOMAINS,
  threshold: 50,
  mode: "enforce" as const,
  customRules: [],
};

function analyze(command: string) {
  return checkDestructive(command, 0, TEST_CONTEXT);
}

function nestSubshells(levels: number, inner: string): string {
  let cmd = inner;
  for (let i = 0; i < levels; i++) {
    cmd = `sh -c ${JSON.stringify(cmd)}`;
  }
  return cmd;
}

describe("Subshell recursion depth", () => {
  test("blocks when subshell nesting exceeds limit", () => {
    const prev = process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH;
    try {
      process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH = "5";
      const cmd = nestSubshells(7, "echo hi");
      const result = analyze(cmd);
      expect(result.blocked).toBe(true);
      if (result.blocked) {
        expect(result.reason).toContain("SUBSHELL DEPTH LIMIT");
      }
    } finally {
      if (prev === undefined) delete process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH;
      else process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH = prev;
    }
  });

  test("allows nesting within limit (non-destructive)", () => {
    const prev = process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH;
    try {
      process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH = "5";
      const cmd = nestSubshells(5, "echo hi");
      const result = analyze(cmd);
      expect(result.blocked).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH;
      else process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH = prev;
    }
  });
});
