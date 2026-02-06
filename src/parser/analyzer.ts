import { parse } from "shell-quote";
import { getConfiguration } from "../config";
import { BlockResult, Config } from "../types";
import { ParsedEntry } from "./types";

// Rules
import { SecurityRule, RuleContext } from "./rules/interface";
import { HomographRule } from "./rules/HomographRule";
import { TerminalInjectionRule } from "./rules/TerminalInjectionRule";
import { RawThreatRule } from "./rules/RawThreatRule";
import { CustomRule } from "./rules/CustomRule";
import { CoreAstRule } from "./rules/CoreAstRule";

// Helper type needed for backward compatibility or direct usage if any
// checkDownloadAndExec was internal before, so we don't need to export it.

const rules: SecurityRule[] = [
  new HomographRule(),
  new TerminalInjectionRule(),
  new RawThreatRule(),
  new CustomRule(),
  new CoreAstRule(),
];

function annotateRule(ruleName: string, result: BlockResult | null): BlockResult | null {
  if (!result) return null;
  if (!result.blocked) return result;
  const blocked = result as Extract<BlockResult, { blocked: true }>;
  return { ...blocked, rule: blocked.rule ?? ruleName };
}

/**
 * Analyzes a shell command for destructive patterns and security threats.
 *
 * This function acts as the main orchestrator, delegating analysis to a set of
 * configured security rules (Strategy Pattern). It handles:
 * 1. String-based checks (fast path for homographs, injection, raw regexes)
 * 2. Shell tokenization (AST generation)
 * 3. AST-based checks (complex logic like context-aware recursion and argument parsing)
 *
 * @param command The raw command string to analyze
 * @param depth Current recursion depth (default: 0). Stops at 5 to prevent stack overflow.
 * @param context Optional configuration context. If omitted, loads from file/env.
 * @returns A BlockResult indicating if the command should be blocked and why.
 */
export function checkDestructive(
  command: string,
  depth = 0,
  context?: Config
): BlockResult {

  const config = context ?? getConfiguration();
  const maxDepth = config.maxSubshellDepth;
  if (depth > maxDepth) {
    return {
      blocked: true,
      reason: "SUBSHELL DEPTH LIMIT EXCEEDED",
      suggestion:
        `Command contains nested subshells beyond the analysis limit (${maxDepth}). ` +
        "Simplify the command, or inspect it manually before running.",
      rule: "Analyzer",
    };
  }


  // 1. Pre-parsing checks (String-based rules)
  const stringContext: RuleContext = {
    command,
    tokens: [], // Empty initially
    config,
    depth,
    recursiveCheck: (cmd, d) => checkDestructive(cmd, d, config),
  };

  for (const rule of rules) {
    if (rule.phase === "pre") {
      const result = annotateRule(rule.name, rule.check(stringContext));
      if (result?.blocked) return result;
    }
  }

  // 2. Parse Command
  const vars: Record<string, string> = {};
  let tokens: ParsedEntry[] = [];
  try {
    tokens = parse(command, (key) => vars[key] || `$${key}`) as ParsedEntry[];
  } catch {
    return {
      blocked: true,
      reason: "MALFORMED COMMAND SYNTAX",
      suggestion: "Command contains invalid shell syntax.",
      rule: "Analyzer",
    };
  }

  // 3. Post-parsing checks (AST-based rules)
  const fullContext: RuleContext = {
    command,
    tokens,
    config,
    depth,
    recursiveCheck: (cmd, d) => checkDestructive(cmd, d, config),
  };

  for (const rule of rules) {
    if (rule.phase === "post") {
      const result = annotateRule(rule.name, rule.check(fullContext));
      if (result?.blocked) return result;
    }
  }

  return { blocked: false };
}
