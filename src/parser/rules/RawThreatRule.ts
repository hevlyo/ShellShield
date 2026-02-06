import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";

/**
 * Rule: Raw Threat Pattern Detection
 * Detects common attack vectors using regex patterns on the raw command string.
 * This includes dangerous pipe-to-shell patterns, encoded payloads, and RCE vectors.
 */
export class RawThreatRule implements SecurityRule {
  readonly name = "RawThreatRule";
  readonly phase = "pre" as const;

  private readonly interpreters = ["sh", "bash", "zsh", "dash", "fish", "pwsh", "powershell", "python\\d*", "perl", "ruby", "node", "bun", "php"];
  private readonly commandFlags = ["-c", "-e", "-command"];

  private readonly patterns: Array<{ pattern: RegExp; reason: string; suggestion: string }> = [
    {
      pattern: /\b(?:pwsh|powershell)\b\s+(?:-encodedcommand|-enc)\b/i,
      reason: "ENCODED POWERSHELL COMMAND DETECTED",
      suggestion: "Encoded PowerShell payloads are high-risk. Decode and review before running.",
    },
    {
      pattern: /eval\s+\$\((curl|wget)\b/i,
      reason: "EVAL-PIPE-TO-SHELL DETECTED",
      suggestion: "Avoid eval with remote content. Download and review the script first.",
    },
    {
      pattern: /eval\s+`(curl|wget)\b/i,
      reason: "EVAL-PIPE-TO-SHELL DETECTED",
      suggestion: "Avoid eval with remote content. Download and review the script first.",
    },
    {
      pattern: new RegExp(`(?:${this.interpreters.join("|")})\\s+(?:${this.commandFlags.join("|")})\\s+["']?\\$\\((curl|wget)\\b`, "i"),
      reason: "COMMAND SUBSTITUTION DETECTED",
      suggestion: "Executing remote scripts via command substitution is dangerous.",
    },
    {
      pattern: new RegExp(`(?:${this.interpreters.join("|")})\\s+(?:${this.commandFlags.join("|")})\\s+["']?\`(curl|wget)\\b`, "i"),
      reason: "COMMAND SUBSTITUTION DETECTED",
      suggestion: "Executing remote scripts via command substitution is dangerous.",
    },
    {
      pattern: /base64\s+-d\s*\|\s*(sh|bash|zsh)\b/i,
      reason: "ENCODED PIPE-TO-SHELL DETECTED",
      suggestion: "Decoding remote content and piping to a shell is dangerous.",
    },
    {
      pattern: /xxd\s+-r\s+-p\s*\|\s*(sh|bash|zsh)\b/i,
      reason: "ENCODED PIPE-TO-SHELL DETECTED",
      suggestion: "Decoding remote content and piping to a shell is dangerous.",
    },
  ];

  check(context: RuleContext): BlockResult | null {
    const { command } = context;

    // Check for deep subshells recursively
    const subshellMatches = command.match(/\b(?:sh|bash|zsh|dash|fish|pwsh|powershell)\s+-c\b/gi) || [];
    if (subshellMatches.length >= 4 && /\b(rm|shred|unlink|wipe|srm|dd)\b/i.test(command)) {
      return {
        blocked: true,
        reason: "DEEP SUBSHELL DETECTED",
        suggestion: "Nested shells can conceal destructive commands. Review the full command before running.",
      };
    }

    for (const entry of this.patterns) {
      if (entry.pattern.test(command)) {
        return {
          blocked: true,
          reason: entry.reason,
          suggestion: entry.suggestion,
        };
      }
    }

    return null;
  }
}
