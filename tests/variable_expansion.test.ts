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

describe("Variable expansion", () => {
  test("blocks command name via $VAR", () => {
    const result = checkDestructive("CMD=rm; $CMD file", 0, TEST_CONTEXT);
    expect(result.blocked).toBe(true);
  });

  test("blocks command name via ${VAR}", () => {
    const result = checkDestructive("CMD=rm; ${CMD} file", 0, TEST_CONTEXT);
    expect(result.blocked).toBe(true);
  });

  test("blocks command name via ${VAR:-default}", () => {
    const result = checkDestructive("${CMD:-rm} file", 0, TEST_CONTEXT);
    expect(result.blocked).toBe(true);
  });
});
