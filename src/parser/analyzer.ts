import { parse } from "shell-quote";
import { getConfiguration } from "../config";
import { SHELL_COMMANDS } from "../constants";
import { BlockResult } from "../types";
import { hasHomograph, checkTerminalInjection } from "../security/validators";
import { isSensitivePath } from "../security/paths";
import { checkPipeToShell } from "./pipe-checks";
import { checkBlockedCommand, checkFindCommand } from "./command-checks";
import { checkSubshellCommand } from "./subshell";
import { ParsedEntry, isOperator } from "./types";

interface AnalysisContext {
  blocked: Set<string>;
  allowed: Set<string>;
  trustedDomains: string[];
  threshold: number;
}

function checkRawThreatPatterns(command: string): BlockResult | null {
  const subshellMatches = command.match(/\b(?:sh|bash|zsh)\s+-c\b/gi) || [];
  if (subshellMatches.length >= 4 && /\b(rm|shred|unlink|wipe|srm|dd)\b/i.test(command)) {
    return {
      blocked: true,
      reason: "DEEP SUBSHELL DETECTED",
      suggestion: "Nested shells can conceal destructive commands. Review the full command before running.",
    };
  }

  const patterns: Array<{ pattern: RegExp; reason: string; suggestion: string }> = [
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
      pattern: /(?:sh|bash|zsh)\s+-c\s+["']?\$\((curl|wget)\b/i,
      reason: "COMMAND SUBSTITUTION DETECTED",
      suggestion: "Executing remote scripts via command substitution is dangerous.",
    },
    {
      pattern: /(?:sh|bash|zsh)\s+-c\s+["']?`(curl|wget)\b/i,
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

  for (const entry of patterns) {
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

function checkDownloadAndExec(remaining: ParsedEntry[], args: string[]): BlockResult | null {
  const outputFlagIndex = args.findIndex(
    (arg) => arg === "-o" || arg === "--output"
  );
  if (outputFlagIndex === -1 || outputFlagIndex + 1 >= args.length) return null;

  const outputPath = args[outputFlagIndex + 1];
  if (!outputPath || outputPath === "/dev/stdout") return null;

  const opIdx = remaining.findIndex(
    (entry) => isOperator(entry) && (entry.op === "&&" || entry.op === ";" || entry.op === "||")
  );
  if (opIdx === -1) return null;

  const nextCmd = remaining[opIdx + 1];
  const nextArg = remaining[opIdx + 2];
  if (typeof nextCmd !== "string" || typeof nextArg !== "string") return null;

  const nextName = nextCmd.split("/").pop()?.toLowerCase() ?? "";
  if (!SHELL_COMMANDS.has(nextName)) return null;

  if (nextArg === outputPath) {
    return {
      blocked: true,
      reason: "DOWNLOAD-AND-EXEC DETECTED",
      suggestion: "Downloading and executing a script in one command is dangerous. Review the script first.",
    };
  }

  return null;
}

export function checkDestructive(
  command: string,
  depth = 0,
  context?: AnalysisContext
): BlockResult {
  if (depth > 5) return { blocked: false };

  const homographRaw = hasHomograph(command);
  if (homographRaw.detected) {
    return {
      blocked: true,
      reason: "HOMOGRAPH ATTACK DETECTED",
      suggestion: `Suspicious character found: ${homographRaw.char}. This may be a visually similar domain masking a malicious source.`,
    };
  }
  const injection = checkTerminalInjection(command);
  if (injection.detected) {
    return {
      blocked: true,
      reason: injection.reason ?? "TERMINAL INJECTION DETECTED",
      suggestion: "Command contains ANSI escape sequences or hidden characters that can manipulate terminal output.",
    };
  }

  const rawThreatCheck = checkRawThreatPatterns(command);
  if (rawThreatCheck) return rawThreatCheck;

  const activeContext = context ?? getConfiguration();
  const vars: Record<string, string> = {};

  let entries: ParsedEntry[] = [];
  try {
    entries = parse(command, (key) => vars[key] || `$${key}`) as ParsedEntry[];
  } catch {
    return {
      blocked: true,
      reason: "MALFORMED COMMAND SYNTAX",
      suggestion: "Command contains invalid shell syntax.",
    };
  }

  let nextMustBeCommand = true;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    if (isOperator(entry)) {
      if (entry.op === "<(") {
        const next = entries[i + 1];
        if (typeof next === "string" && (next === "curl" || next === "wget")) {
          return {
            blocked: true,
            reason: "PROCESS SUBSTITUTION DETECTED",
            suggestion: "Executing remote scripts via process substitution is dangerous.",
          };
        }
      }
      nextMustBeCommand = true;
      continue;
    }

    if (typeof entry !== "string") {
      continue;
    }

    if (!nextMustBeCommand) {
      if (entry.includes("=") && !entry.startsWith("-")) {
        const [key, ...valParts] = entry.split("=");
        if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
          vars[key] = valParts.join("=");
        }
      }

      if ((entry === "-o" || entry === "-O" || entry === "--output") && i + 1 < entries.length) {
        const outputPath = entries[i + 1];
        if (typeof outputPath === "string" && isSensitivePath(outputPath)) {
          return {
            blocked: true,
            reason: "SENSITIVE PATH TARGETED",
            suggestion: `Command is attempting to write directly to a critical configuration file: ${outputPath}`,
          };
        }
      }
      continue;
    }

    nextMustBeCommand = false;

    if (entry.includes("=") && !entry.startsWith("-")) {
      const [key, ...valParts] = entry.split("=");
      if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
        vars[key] = valParts.join("=");
      }
      nextMustBeCommand = true;
      continue;
    }

    const normalizedEntry = entry.toLowerCase();

    if (normalizedEntry === "curl" || normalizedEntry === "wget") {
      const remaining = entries.slice(i + 1);
      const args = remaining.filter((item) => typeof item === "string") as string[];
      const pipeCheck = checkPipeToShell(args, remaining, activeContext.trustedDomains);
      if (pipeCheck) return pipeCheck;

      const downloadExecCheck = checkDownloadAndExec(remaining, args);
      if (downloadExecCheck) return downloadExecCheck;
    }

    if (normalizedEntry === "bash" || normalizedEntry === "sh" || normalizedEntry === "zsh") {
      const remaining = entries.slice(i + 1);
      if (
        remaining.some(
          (item) =>
            typeof item === "string" &&
            (item.includes("<(curl") ||
              item.includes("<(wget") ||
              item.includes("< <(curl") ||
              item.includes("< <(wget"))
        )
      ) {
        return {
          blocked: true,
          reason: "PROCESS SUBSTITUTION DETECTED",
          suggestion: "Executing remote scripts via process substitution is dangerous.",
        };
      }
    }

    if (["sudo", "xargs", "command", "env"].includes(normalizedEntry)) {
      nextMustBeCommand = true;
      continue;
    }

    if (normalizedEntry === "git" && i + 1 < entries.length) {
      const next = entries[i + 1];
      if (typeof next === "string" && next.toLowerCase() === "rm") {
        i++;
        continue;
      }
    }

    const basenamePart = entry.split("/").pop() ?? "";
    const cmdName = entry.startsWith("\\") ? entry.slice(1) : basenamePart;

    let resolvedCmd = cmdName.toLowerCase();
    if (cmdName.startsWith("$")) {
      const varName = cmdName.slice(1);
      resolvedCmd = (vars[varName] || cmdName).split("/").pop()?.toLowerCase() ?? "";
    }

    if (activeContext.allowed.has(resolvedCmd)) {
      continue;
    }

    const args = entries.slice(i + 1).filter((item) => typeof item === "string") as string[];

    const blockedCheck = checkBlockedCommand(resolvedCmd, args, {
      blocked: activeContext.blocked,
      threshold: activeContext.threshold,
    });
    if (blockedCheck) return blockedCheck;

    if (resolvedCmd === "find") {
      const remaining = entries.slice(i + 1);
      const findCheck = checkFindCommand(remaining, activeContext.blocked);
      if (findCheck) return findCheck;
    }

    if (SHELL_COMMANDS.has(resolvedCmd)) {
      const subshellResult = checkSubshellCommand(entries, i + 1, (subshellCmd) => {
        const result = checkDestructive(subshellCmd, depth + 1, activeContext);
        return result.blocked ? result : null;
      });
      if (subshellResult?.blocked) return subshellResult;
    }
  }

  return { blocked: false };
}
