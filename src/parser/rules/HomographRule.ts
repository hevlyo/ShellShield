import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";
import { hasHomograph } from "../../security/validators";

/**
 * Rule: Homograph Attack Detection
 * Detects usage of non-ASCII characters that look visually identical to ASCII characters
 * (e.g., Cyrillic 'a' vs Latin 'a') which can be used to spoof commands or domains.
 */
export class HomographRule implements SecurityRule {
  readonly name = "HomographRule";

  check(context: RuleContext): BlockResult | null {
    const { detected, char } = hasHomograph(context.command);
    
    if (detected) {
      return {
        blocked: true,
        reason: "HOMOGRAPH ATTACK DETECTED",
        suggestion: `Suspicious character found: ${char}. This may be a visually similar domain masking a malicious source.`,
      };
    }
    
    return null;
  }
}
