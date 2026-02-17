import { BlockResult } from "../types";
import { isCriticalPath } from "../security/paths";
import { hasUncommittedChanges } from "../integrations/git";
import { SYSTEMCTL_DESTRUCTIVE_SUBCOMMANDS } from "../constants";
import { ParsedEntry } from "./types";
import { filterFlags, getTrashSuggestion, normalizeCommandName } from "./utils";

const ADDITIONAL_DANGEROUS_COMMANDS = new Set(["rm", "shred", "dd", "mkfs"]);
const EXECUTOR_COMMANDS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "fish",
  "pwsh",
  "powershell",
  "python",
  "python2",
  "python3",
  "perl",
  "ruby",
  "node",
  "bun",
  "php",
  ".",
  "source",
]);

interface BlockedContext {
  blocked: Set<string>;
  threshold: number;
}

function checkGitIntegration(targetFiles: string[]): BlockResult | null {
  const uncommitted = hasUncommittedChanges(targetFiles);
  if (uncommitted.length > 0) {
    return {
      blocked: true,
      reason: "UNCOMMITTED CHANGES DETECTED",
      suggestion: `Commit changes to these files first: ${uncommitted.join(", ")}`,
    };
  }
  return null;
}

export function checkBlockedCommand(
  resolvedCmd: string,
  args: string[],
  context: BlockedContext
): BlockResult | null {
  if (resolvedCmd === "dd") {
    if (args.some((arg) => arg.toLowerCase().startsWith("of="))) {
      return {
        blocked: true,
        reason: "Destructive dd detected",
        suggestion: "be careful with dd of=",
      };
    }
    return null;
  }

  if (resolvedCmd === "mv" || resolvedCmd === "cp") {
    for (const arg of args) {
      if (!arg.startsWith("-") && isCriticalPath(arg)) {
        return {
          blocked: true,
          reason: "CRITICAL PATH TARGETED",
          suggestion: `Modifying critical system path ${arg} is prohibited.`,
        };
      }
    }
  }

  if (resolvedCmd === "chmod" || resolvedCmd === "chown" || resolvedCmd === "chgrp") {
    const hasRecursive = args.some((arg) =>
      arg === "-R" ||
      arg === "--recursive" ||
      (arg.startsWith("-") && !arg.startsWith("--") && arg.includes("R"))
    );
    if (hasRecursive) {
      for (const arg of args) {
        if (!arg.startsWith("-") && isCriticalPath(arg)) {
          return {
            blocked: true,
            reason: "CRITICAL PATH TARGETED",
            suggestion: `Recursive ${resolvedCmd} on critical system path ${arg} is prohibited.`,
          };
        }
      }
    }
  }

  if (resolvedCmd === "systemctl") {
    const subcommand = args.find((arg) => !arg.startsWith("-"));
    if (subcommand && SYSTEMCTL_DESTRUCTIVE_SUBCOMMANDS.has(subcommand.toLowerCase())) {
      return {
        blocked: true,
        reason: `Destructive systemctl ${subcommand} detected`,
        suggestion: `systemctl ${subcommand} can disrupt system services. Review before running.`,
      };
    }
    return null;
  }

  if (!context.blocked.has(resolvedCmd)) return null;

  for (const arg of args) {
    if (!arg.startsWith("-") && isCriticalPath(arg)) {
      return {
        blocked: true,
        reason: "CRITICAL PATH PROTECTED",
        suggestion: `Permanent deletion of ${arg} is prohibited.`,
      };
    }
  }

  const targetFiles = filterFlags(args);
  if (targetFiles.length > context.threshold) {
    return {
      blocked: true,
      reason: "VOLUME THRESHOLD EXCEEDED",
      suggestion: `You are trying to delete ${targetFiles.length} files. Use a more specific command.`,
    };
  }

  const gitCheck = checkGitIntegration(targetFiles);
  if (gitCheck) return gitCheck;

  let suggestion = getTrashSuggestion([]);
  if (resolvedCmd === "rm" && targetFiles.length > 0) {
    suggestion = getTrashSuggestion(targetFiles);
  }

  return {
    blocked: true,
    reason: `Destructive command '${resolvedCmd}' detected`,
    suggestion,
  };
}

function isDangerousExec(execCmd: ParsedEntry, dangerousCommands: Set<string>): boolean {
  if (typeof execCmd !== "string") return false;
  const execName = normalizeCommandName(execCmd);
  return dangerousCommands.has(execName);
}

export function checkFindCommand(
  remaining: ParsedEntry[],
  blockedCommands: Set<string>
): BlockResult | null {
  const dangerousCommands = new Set([
    ...blockedCommands,
    ...ADDITIONAL_DANGEROUS_COMMANDS,
    ...EXECUTOR_COMMANDS,
  ]);
  
  if (remaining.some((entry) => typeof entry === "string" && entry.toLowerCase() === "-delete")) {
    return { blocked: true, reason: "find -delete detected", suggestion: getTrashSuggestion([]) };
  }

  const findFlags = ["-exec", "-execdir", "-ok"];
  for (const flag of findFlags) {
    const idx = remaining.findIndex(
      (entry) => typeof entry === "string" && entry.toLowerCase() === flag
    );
    if (idx !== -1 && idx + 1 < remaining.length) {
      const execCmd = remaining[idx + 1];
      if (isDangerousExec(execCmd, dangerousCommands)) {
        return {
          blocked: true,
          reason: `find ${flag} ${execCmd} detected${flag === "-ok" ? " - dangerous command" : ""}`,
          suggestion: getTrashSuggestion([]),
        };
      }
    }
  }

  return null;
}
