import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";
import {
  SHELL_INTERPRETERS,
  DOWNLOAD_COMMANDS,
  CODE_EXECUTION_FLAGS,
  PIPE_PATTERNS,
  PROCESS_SUBSTITUTION_PATTERNS,
  EVAL_PATTERNS,
  POWERSHELL_PATTERNS,
  safeRegexTest,
  MAX_INPUT_LENGTH,
} from "../../security/patterns";

/**
 * Rule: Raw Threat Pattern Detection
 * Detects common attack vectors using regex patterns on the raw command string.
 * This includes dangerous pipe-to-shell patterns, encoded payloads, and RCE vectors.
 */
export class RawThreatRule implements SecurityRule {
  readonly name = "RawThreatRule";
  readonly phase = "pre" as const;

  private readonly interpreters = [
    ...SHELL_INTERPRETERS.map(i => `\\b${i}\\b`),
    "\\bpython\\d*(?:\\.\\d+)*\\b",
    "\\bperl\\b",
    "\\bruby\\b",
    "\\bnode\\b",
    "\\bbun\\b",
    "\\bphp\\d*(?:\\.\\d+)*\\b"
  ];
  private readonly commandFlags = CODE_EXECUTION_FLAGS;

  private readonly patterns: Array<{ pattern: RegExp; reason: string; suggestion: string }> = [
    {
      pattern: POWERSHELL_PATTERNS.encodedCommand,
      reason: "ENCODED POWERSHELL COMMAND DETECTED",
      suggestion: "Encoded PowerShell payloads are high-risk. Decode and review before running.",
    },
    {
      pattern: EVAL_PATTERNS.withCurl,
      reason: "EVAL-PIPE-TO-SHELL DETECTED",
      suggestion: "Avoid eval with remote content. Download and review the script first.",
    },
    {
      pattern: EVAL_PATTERNS.withWget,
      reason: "EVAL-PIPE-TO-SHELL DETECTED",
      suggestion: "Avoid eval with remote content. Download and review the script first.",
    },
    {
      pattern: EVAL_PATTERNS.withBacktickCurl,
      reason: "EVAL-PIPE-TO-SHELL DETECTED",
      suggestion: "Avoid eval with remote content. Download and review the script first.",
    },
    {
      pattern: EVAL_PATTERNS.withBacktickWget,
      reason: "EVAL-PIPE-TO-SHELL DETECTED",
      suggestion: "Avoid eval with remote content. Download and review the script first.",
    },
    {
      pattern: new RegExp(`(?:${this.interpreters.join("|")})\\s{0,10}(?:${this.commandFlags.join("|")})\\s{0,10}["']?\\$\\((?:${DOWNLOAD_COMMANDS.join("|")})\\b`, "i"),
      reason: "COMMAND SUBSTITUTION DETECTED",
      suggestion: "Executing remote scripts via command substitution is dangerous.",
    },
    {
      pattern: new RegExp(`(?:${this.interpreters.join("|")})\\s{0,10}(?:${this.commandFlags.join("|")})\\s{0,10}["']?\`(?:${DOWNLOAD_COMMANDS.join("|")})\\b`, "i"),
      reason: "COMMAND SUBSTITUTION DETECTED",
      suggestion: "Executing remote scripts via command substitution is dangerous.",
    },
    {
      pattern: PIPE_PATTERNS.base64ToShell,
      reason: "ENCODED PIPE-TO-SHELL DETECTED",
      suggestion: "Decoding remote content and piping to a shell is dangerous.",
    },
    {
      pattern: PIPE_PATTERNS.xxdToShell,
      reason: "ENCODED PIPE-TO-SHELL DETECTED",
      suggestion: "Decoding remote content and piping to a shell is dangerous.",
    },
    {
      pattern: PIPE_PATTERNS.downloadToInterpreter,
      reason: "PIPE-TO-INTERPRETER DETECTED",
      suggestion: "Piping remote content to an interpreter is dangerous. Download and review first.",
    },
    {
      pattern: PIPE_PATTERNS.sedToShell,
      reason: "SED-PIPE-TO-SHELL DETECTED",
      suggestion: "Piping sed output to a shell can be dangerous. Review the command carefully.",
    },
    {
      pattern: PIPE_PATTERNS.awkToShell,
      reason: "AWK-PIPE-TO-SHELL DETECTED",
      suggestion: "Piping awk output to a shell can be dangerous. Review the command carefully.",
    },
    {
      pattern: PROCESS_SUBSTITUTION_PATTERNS.standard,
      reason: "PROCESS SUBSTITUTION DETECTED",
      suggestion: "Process substitution with remote content is dangerous.",
    },
    {
      pattern: PIPE_PATTERNS.opensslToShell,
      reason: "OPENSSL-PIPE-TO-SHELL DETECTED",
      suggestion: "Piping openssl output to a shell is suspicious. Review carefully.",
    },
    {
      pattern: PIPE_PATTERNS.tarToShell,
      reason: "TAR-PIPE-TO-SHELL DETECTED",
      suggestion: "Piping tar output to a shell is dangerous. Extract first, then review.",
    },
  ];

  check(context: RuleContext): BlockResult | null {
    const { command } = context;

    // Fail-closed on long commands to prevent ReDoS bypass
    if (command.length > MAX_INPUT_LENGTH) {
      return {
        blocked: true,
        reason: "COMMAND TOO LONG",
        suggestion: "The command exceeds the analysis limit. Inspect manually or simplify.",
      };
    }

    // Check for deep subshells recursively - bounded repetitions
    const subshellMatches = command.match(/\b(?:sh|bash|zsh|dash|fish|pwsh|powershell)\b\s{0,10}-c\b/gi) || [];
    if (subshellMatches.length >= 4 && /\b(?:rm|shred|unlink|wipe|srm|dd)\b/i.test(command)) {
      return {
        blocked: true,
        reason: "DEEP SUBSHELL DETECTED",
        suggestion: "Nested shells can conceal destructive commands. Review the full command before running.",
      };
    }

    for (const entry of this.patterns) {
      if (safeRegexTest(entry.pattern, command)) {
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
