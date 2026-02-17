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
  maxSubshellDepth: 5,
};

function analyze(command: string) {
  return checkDestructive(command, 0, TEST_CONTEXT);
}

describe("New bypasses that SHOULD be blocked", () => {
  test("CMD=rm; $CMD file (variable expansion)", () => {
    const result = analyze("CMD=rm; $CMD file");
    expect(result.blocked).toBe(true);
  });

  test("sh -c 'sh -c \"rm file\"' (nested subshell)", () => {
    const result = analyze("sh -c 'sh -c \"rm file\"'");
    expect(result.blocked).toBe(true);
  });

  test("deeply nested subshells (4 levels)", () => {
    const result = analyze("sh -c sh -c sh -c sh -c rm file");
    expect(result.blocked).toBe(true);
  });

  test("wipe file.txt", () => {
    const result = analyze("wipe file.txt");
    expect(result.blocked).toBe(true);
  });

  test("srm file.txt", () => {
    const result = analyze("srm file.txt");
    expect(result.blocked).toBe(true);
  });

  test("RM -rf dir (case insensitivity)", () => {
    const result = analyze("RM -rf dir");
    expect(result.blocked).toBe(true);
  });

  test("dd if=/dev/zero of=file.txt (destructive dd)", () => {
    const result = analyze("dd if=/dev/zero of=important_file");
    expect(result.blocked).toBe(true);
  });
});

describe("Improved UX", () => {
  test("suggests trash command for rm", () => {
    const result = analyze("rm file.txt");
    expect(result.blocked).toBe(true);
    if (result.blocked) {
      expect(result.suggestion).toContain("trash file.txt");
    }
  });

  test("suggests trash command for rm -rf", () => {
    const result = analyze("rm -rf folder/");
    expect(result.blocked).toBe(true);
    if (result.blocked) {
      expect(result.suggestion).toContain("trash folder/");
    }
  });

  test("does not mix next command arguments into rm suggestion", () => {
    const result = analyze("rm file.txt && echo done");
    expect(result.blocked).toBe(true);
    if (result.blocked) {
      expect(result.suggestion).toContain("trash file.txt");
      expect(result.suggestion).not.toContain("echo");
      expect(result.suggestion).not.toContain("done");
    }
  });
});

describe("Configuration", () => {
  test("allows custom blocked commands via env", () => {
    const prev = process.env.OPENCODE_BLOCK_COMMANDS;
    try {
      process.env.OPENCODE_BLOCK_COMMANDS = "custom-delete,another-one";
      const result = checkDestructive("custom-delete file");
      expect(result.blocked).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.OPENCODE_BLOCK_COMMANDS;
      else process.env.OPENCODE_BLOCK_COMMANDS = prev;
    }
  });

  test("allows custom allowed commands via env", () => {
    const prev = process.env.OPENCODE_ALLOW_COMMANDS;
    try {
      process.env.OPENCODE_ALLOW_COMMANDS = "rm";
      const result = checkDestructive("rm safe-file");
      expect(result.blocked).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.OPENCODE_ALLOW_COMMANDS;
      else process.env.OPENCODE_ALLOW_COMMANDS = prev;
    }
  });
});
