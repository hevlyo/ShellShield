import { SHELL_COMMANDS } from "../constants";
import { isTrustedDomain } from "../security/validators";
import { BlockResult } from "../types";
import { ParsedEntry, isOperator } from "./types";
import { normalizeCommandName } from "./utils";

const INSECURE_FLAGS = new Set(["-k", "--insecure", "--no-check-certificate"]);

export function checkPipeToShell(
  args: string[],
  remaining: ParsedEntry[],
  trustedDomains: string[]
): BlockResult | null {
  for (const arg of args) {
    if (arg.includes("://") && arg.includes("@")) {
      try {
        const urlObj = new URL(arg);
        if (urlObj.username || urlObj.password) {
          return {
            blocked: true,
            reason: "CREDENTIAL EXPOSURE DETECTED",
            suggestion: "Commands should not include credentials in URLs. Use environment variables or netrc.",
          };
        }
      } catch {
        continue;
      }
    }
  }

  const pipeIdx = remaining.findIndex(
    (entry) => isOperator(entry) && entry.op === "|"
  );
  if (pipeIdx === -1) return null;

  const nextPart = remaining[pipeIdx + 1];
  if (typeof nextPart !== "string") return null;

  const nextCmd = normalizeCommandName(nextPart);
  if (!SHELL_COMMANDS.has(nextCmd)) return null;

  const url = args.find((arg) => arg.startsWith("http"));
  if (url && isTrustedDomain(url, trustedDomains)) {
    return null;
  }

  if (args.some((arg) => arg.startsWith("http://"))) {
    return {
      blocked: true,
      reason: "INSECURE TRANSPORT DETECTED",
      suggestion: "Piping plain HTTP content to a shell is dangerous. Use HTTPS.",
    };
  }

  if (args.some((arg) => INSECURE_FLAGS.has(arg))) {
    return {
      blocked: true,
      reason: "INSECURE TRANSPORT DETECTED",
      suggestion: "Piping to a shell with certificate validation disabled is extremely dangerous.",
    };
  }

  return {
    blocked: true,
    reason: "PIPE-TO-SHELL DETECTED",
    suggestion: "Executing remote scripts directly via pipe is dangerous. Download and review the script first.",
  };
}
