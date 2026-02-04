import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";
import { checkTerminalInjection } from "../../security/validators";

/**
 * Rule: Terminal Injection Detection
 * Detects ANSI escape sequences or hidden characters (zero-width) that could
 * manipulate the terminal output to hide malicious actions.
 */
export class TerminalInjectionRule implements SecurityRule {
  readonly name = "TerminalInjectionRule";
  readonly phase = "pre" as const;

  check(context: RuleContext): BlockResult | null {
    const injection = checkTerminalInjection(context.command);
    
    if (injection.detected) {
      return {
        blocked: true,
        reason: injection.reason ?? "TERMINAL INJECTION DETECTED",
        suggestion: "Command contains ANSI escape sequences or hidden characters that can manipulate terminal output.",
      };
    }
    
    return null;
  }
}
