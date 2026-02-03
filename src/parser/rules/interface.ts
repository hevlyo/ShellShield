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
}

/**
 * Interface for a security rule that analyzes a command.
 * Applying the Strategy Pattern allows easy addition of new checks.
 */
export interface SecurityRule {
  /** Unique name of the rule for debugging/logging */
  name: string;
  
  /**
   * Analyzes the command context for security violations.
   * @param context The analysis context containing command, tokens, and config
   * @returns A BlockResult if a violation is found, or null if passed
   */
  check(context: RuleContext): BlockResult | null;
}
