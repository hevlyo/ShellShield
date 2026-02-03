import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";

/**
 * Rule: Custom Regex Rules
 * Checks the command against user-defined regex patterns from the configuration.
 */
export class CustomRule implements SecurityRule {
  readonly name = "CustomRule";

  check(context: RuleContext): BlockResult | null {
    const { config, command } = context;
    
    if (config.customRules) {
      for (const rule of config.customRules) {
        try {
          const regex = new RegExp(rule.pattern);
          if (regex.test(command)) {
            return {
              blocked: true,
              reason: "CUSTOM RULE VIOLATION",
              suggestion: rule.suggestion,
            };
          }
        } catch (e) {
          if (process.env.DEBUG) console.error("Invalid custom rule regex:", rule.pattern);
        }
      }
    }
    
    return null;
  }
}
