import { SHELL_COMMANDS } from "../constants";
import { isTrustedDomain } from "../security/validators";
import { BlockResult } from "../types";
import { ParsedEntry, isOperator } from "./types";
import { normalizeCommandName } from "./utils";

const INSECURE_FLAGS = new Set(["-k", "--insecure", "--no-check-certificate"]);
const CONTROL_OPERATORS = new Set(["&&", "||", ";", "&"]);

function checkUrlCredentials(args: string[]): BlockResult | null {
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
  return null;
}

function checkTransportSecurity(args: string[]): BlockResult | null {
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
  return null;
}

function getPipeTargets(remaining: ParsedEntry[]): string[] {
  const targets: string[] = [];

  for (let i = 0; i < remaining.length; i++) {
    const entry = remaining[i];
    if (!isOperator(entry)) continue;

    if (CONTROL_OPERATORS.has(entry.op)) break;
    if (entry.op !== "|" && entry.op !== "|&") continue;

    for (let j = i + 1; j < remaining.length; j++) {
      const next = remaining[j];
      if (isOperator(next)) {
        if (CONTROL_OPERATORS.has(next.op)) return targets;
        if (next.op === "|" || next.op === "|&") break;
        continue;
      }
      if (typeof next === "string") {
        targets.push(normalizeCommandName(next));
      }
      break;
    }
  }

  return targets;
}

function getFirstUrlArg(args: string[]): string | null {
  for (const arg of args) {
    if (arg.startsWith("https://") || arg.startsWith("http://")) {
      return arg;
    }
  }
  return null;
}

export function checkPipeToShell(
  args: string[],
  remaining: ParsedEntry[],
  trustedDomains: string[]
): BlockResult | null {
  const credentialCheck = checkUrlCredentials(args);
  if (credentialCheck) return credentialCheck;

  const pipeTargets = getPipeTargets(remaining);
  if (pipeTargets.length === 0) return null;
  const hasShellPipe = pipeTargets.some((cmd) => SHELL_COMMANDS.has(cmd));
  if (!hasShellPipe) return null;

  const transportCheck = checkTransportSecurity(args);
  if (transportCheck) return transportCheck;

  const url = getFirstUrlArg(args);
  const isDirectShellPipe =
    pipeTargets.length === 1 && SHELL_COMMANDS.has(pipeTargets[0]);

  if (url && isDirectShellPipe && isTrustedDomain(url, trustedDomains)) {
    return null;
  }

  return {
    blocked: true,
    reason: "PIPE-TO-SHELL DETECTED",
    suggestion: "Executing remote scripts directly via pipe is dangerous. Download and review the script first.",
  };
}
