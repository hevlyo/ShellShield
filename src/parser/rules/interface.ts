import { Config, BlockResult } from "../../types";
import { ParsedEntry } from "../types";

/**
 * Context provided to each security rule during analysis.
 */
export interface RuleContext {
  /** The raw command string provided by the user */
  command: string;
  /** The parsed shell tokens (AST-like structure) */
  tokens: ParsedEntry[];
  /** The full ShellShield configuration */
  config: Config;
  /** Current recursion depth for subshells (starts at 0) */
  depth: number;
  /**
   * Recursive analysis function for subshells.
   * This allows rules to trigger analysis of nested commands without importing the analyzer directly.
   */
  recursiveCheck: (command: string, depth: number) => BlockResult;
}

/**
 * Interface for a security rule that analyzes a command.
 * Applying the Strategy Pattern allows easy addition of new checks.
 */
export interface SecurityRule {
  /** Unique name of the rule for debugging/logging */
  name: string;

  /**
   * Execution phase for the rule.
   * - pre: runs before shell parsing (fast string checks)
   * - post: runs after parsing (token/AST checks)
   */
  phase: "pre" | "post";
  
  /**
   * Analyzes the command context for security violations.
   * @param context The analysis context containing command, tokens, and config
   * @returns A BlockResult if a violation is found, or null if passed
   */
  check(context: RuleContext): BlockResult | null;
}
