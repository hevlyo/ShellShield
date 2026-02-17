import { describe, expect, test } from "bun:test";
import {
  PIPE_PATTERNS,
  PROCESS_SUBSTITUTION_PATTERNS,
  EVAL_PATTERNS,
  POWERSHELL_PATTERNS,
  safeRegexTest,
  validatePatternPerformance,
} from "../src/security/patterns";

describe("Regex Security - ReDoS Prevention", () => {
  test("safeRegexTest rejects oversized inputs", () => {
    const pattern = /test/i;
    const smallInput = "test";
    const largeInput = "a".repeat(15000);

    expect(safeRegexTest(pattern, smallInput)).toBe(true);
    expect(safeRegexTest(pattern, largeInput)).toBe(false);
  });

  test("downloadToInterpreter pattern handles malicious input efficiently", () => {
    const pattern = PIPE_PATTERNS.downloadToInterpreter;

    const normalInput = "curl https://example.com/script.py | python";
    expect(validatePatternPerformance(pattern, normalInput, 50)).toBe(true);

    const maliciousInput = "curl " + "a".repeat(1000) + " | python";
    expect(validatePatternPerformance(pattern, maliciousInput, 100)).toBe(true);
  });

  test("sedToShell pattern handles long inputs without backtracking", () => {
    const pattern = PIPE_PATTERNS.sedToShell;

    const normalInput = "sed 's/foo/bar/' file.txt | bash";
    expect(validatePatternPerformance(pattern, normalInput, 50)).toBe(true);

    const longInput = "sed " + "'s/a/b/' ".repeat(100) + "| bash";
    expect(validatePatternPerformance(pattern, longInput, 100)).toBe(true);
  });

  test("all patterns reject inputs exceeding max length", () => {
    const allPatterns = [
      ...Object.values(PIPE_PATTERNS),
      ...Object.values(PROCESS_SUBSTITUTION_PATTERNS),
      ...Object.values(EVAL_PATTERNS),
      ...Object.values(POWERSHELL_PATTERNS),
    ];

    const oversizedInput = "test".repeat(3000);

    for (const pattern of allPatterns) {
      expect(safeRegexTest(pattern, oversizedInput)).toBe(false);
    }
  });

  test("validatePatternPerformance honors max duration threshold", () => {
    const result = validatePatternPerformance(/test/, "test", -1);
    expect(result).toBe(false);
  });
});
