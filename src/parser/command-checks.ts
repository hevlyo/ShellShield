import { BlockResult } from "../types";
import { isCriticalPath } from "../security/paths";
import { hasUncommittedChanges } from "../integrations/git";
import { ParsedEntry } from "./types";
import { filterFlags, getTrashSuggestion, normalizeCommandName } from "./utils";

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

export function checkFindCommand(
  remaining: ParsedEntry[],
  blockedCommands: Set<string>
): BlockResult | null {
  const hasDelete = remaining.some((entry) => typeof entry === "string" && entry.toLowerCase() === "-delete");
  if (hasDelete) {
    return { blocked: true, reason: "find -delete detected", suggestion: getTrashSuggestion([]) };
  }

  const execIdx = remaining.findIndex(
    (entry) => typeof entry === "string" && entry.toLowerCase() === "-exec"
  );
  if (execIdx !== -1 && execIdx + 1 < remaining.length) {
    const execCmd = remaining[execIdx + 1];
    if (typeof execCmd === "string") {
      const execName = normalizeCommandName(execCmd);
      if (blockedCommands.has(execName)) {
        return {
          blocked: true,
          reason: `find -exec ${execCmd} detected`,
          suggestion: getTrashSuggestion([]),
        };
      }
    }
  }

  return null;
}
