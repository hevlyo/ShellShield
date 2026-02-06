import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";
import { isOperator, ParsedEntry } from "../types";
import { checkPipeToShell } from "../pipe-checks";
import { checkBlockedCommand, checkFindCommand } from "../command-checks";
import { checkSubshellCommand } from "../subshell";
import { SHELL_COMMANDS } from "../../constants";
import { isSensitivePath } from "../../security/paths";
import { getShellContextEntry, findBlockedTokenInShellContext } from "../../shell-context";

/**
 * Rule: Core AST Analysis
 * Iterates through parsed shell tokens to detect complex threats like:
 * - Process substitution (<(curl ...))
 * - Sensitive path writes (-o /etc/passwd)
 * - Dangerous pipes (curl | bash)
 * - Blocked commands (rm, mv critical paths)
 * - Recursive subshells
 */
export class CoreAstRule implements SecurityRule {
  readonly name = "CoreAstRule";
  readonly phase = "post" as const;

  private checkEnvironmentVariable(entry: string, vars: Record<string, string>): boolean {
    if (entry.includes("=") && !entry.startsWith("-")) {
      const [key, ...valParts] = entry.split("=");
      if (/^\w+$/.test(key)) {
        vars[key] = valParts.join("=");
        return true;
      }
    }
    return false;
  }

  private checkSensitivePathWrite(entry: string, tokens: ParsedEntry[], i: number): BlockResult | null {
    if ((entry === "-o" || entry === "-O" || entry === "--output") && i + 1 < tokens.length) {
      const outputPath = tokens[i + 1];
      if (typeof outputPath === "string" && isSensitivePath(outputPath)) {
        return {
          blocked: true,
          reason: "SENSITIVE PATH TARGETED",
          suggestion: `Command is attempting to write directly to a critical configuration file: ${outputPath}`,
        };
      }
    }
    return null;
  }

  private checkCurlWget(normalizedEntry: string, tokens: ParsedEntry[], i: number, config: any): BlockResult | null {
    if (normalizedEntry === "curl" || normalizedEntry === "wget") {
      const remaining = tokens.slice(i + 1);
      const args = remaining.filter((item) => typeof item === "string") as string[];
      const pipeCheck = checkPipeToShell(args, remaining, config.trustedDomains);
      if (pipeCheck) return pipeCheck;

      return this.checkDownloadAndExec(remaining, args);
    }
    return null;
  }

  private checkProcessSubstitution(normalizedEntry: string, tokens: ParsedEntry[], i: number): BlockResult | null {
    if (normalizedEntry === "bash" || normalizedEntry === "sh" || normalizedEntry === "zsh") {
      const remaining = tokens.slice(i + 1);
      const hasSubstitution = remaining.some(
        (item) =>
          typeof item === "string" &&
          (item.includes("<(curl") ||
            item.includes("<(wget") ||
            item.includes("< <(curl") ||
            item.includes("< <(wget"))
      );
      if (hasSubstitution) {
        return {
          blocked: true,
          reason: "PROCESS SUBSTITUTION DETECTED",
          suggestion: "Executing remote scripts via process substitution is dangerous.",
        };
      }
    }
    return null;
  }

  private checkShellContext(resolvedCmd: string, config: any): BlockResult | null {
    if (!config.blocked.has(resolvedCmd)) {
      const ctxEntry = getShellContextEntry(resolvedCmd);
      if (ctxEntry && (ctxEntry.kind === "alias" || ctxEntry.kind === "function")) {
        const hit = findBlockedTokenInShellContext(ctxEntry, config.blocked);
        if (hit && hit !== resolvedCmd) {
          return {
            blocked: true,
            reason: "SHELL CONTEXT OVERRIDE DETECTED",
            suggestion:
              `Your shell ${ctxEntry.kind} for '${resolvedCmd}' references '${hit}'. ` +
              `Inspect with: type ${resolvedCmd}. Prefer bypass with: \\${resolvedCmd} or command ${resolvedCmd}.`,
          };
        }
      }
    }
    return null;
  }

  check(context: RuleContext): BlockResult | null {
    const { tokens, config, depth, recursiveCheck } = context;
    const vars: Record<string, string> = {};
    let nextMustBeCommand = true;

    for (let i = 0; i < tokens.length; i++) {
      const entry = tokens[i];

      if (isOperator(entry)) {
        if (entry.op === "<(") {
          const next = tokens[i + 1];
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
        this.checkEnvironmentVariable(entry, vars);
        const pathCheck = this.checkSensitivePathWrite(entry, tokens, i);
        if (pathCheck) return pathCheck;
        continue;
      }

      nextMustBeCommand = false;

      if (this.checkEnvironmentVariable(entry, vars)) {
        nextMustBeCommand = true;
        continue;
      }

      const normalizedEntry = entry.toLowerCase();

      const curlCheck = this.checkCurlWget(normalizedEntry, tokens, i, config);
      if (curlCheck) return curlCheck;

      const subCheck = this.checkProcessSubstitution(normalizedEntry, tokens, i);
      if (subCheck) return subCheck;

      if (["sudo", "xargs", "command", "env"].includes(normalizedEntry)) {
        nextMustBeCommand = true;
        continue;
      }

      if (normalizedEntry === "git" && i + 1 < tokens.length) {
        const next = tokens[i + 1];
        if (typeof next === "string" && next.toLowerCase() === "rm") {
          i++;
          continue;
        }
      }

      const basenamePart = entry.split("/").pop() ?? "";
      const cmdName = entry.startsWith("\\") ? entry.slice(1) : basenamePart;

      let resolvedCmd = cmdName.toLowerCase();
      const resolvedVar = this.resolveVarToken(cmdName, vars);
      if (resolvedVar) {
        resolvedCmd = resolvedVar.split("/").pop()?.toLowerCase() ?? "";
      }

      const ctxCheck = this.checkShellContext(resolvedCmd, config);
      if (ctxCheck) return ctxCheck;

      if (config.allowed.has(resolvedCmd)) {
        continue;
      }

      const args = tokens.slice(i + 1).filter((item) => typeof item === "string") as string[];

      const blockedCheck = checkBlockedCommand(resolvedCmd, args, {
        blocked: config.blocked,
        threshold: config.threshold,
      });
      if (blockedCheck) return blockedCheck;

      if (resolvedCmd === "find") {
        const findCheck = checkFindCommand(tokens.slice(i + 1), config.blocked);
        if (findCheck) return findCheck;
      }

      if (SHELL_COMMANDS.has(resolvedCmd)) {
        const subshellResult = checkSubshellCommand(tokens, i + 1, (subshellCmd) => {
          return recursiveCheck(subshellCmd, depth + 1);
        });
        if (subshellResult?.blocked) return subshellResult;
      }
    }

    return null;
  }

  private checkDownloadAndExec(remaining: ParsedEntry[], args: string[]): BlockResult | null {
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

  private resolveVarToken(token: string, vars: Record<string, string>): string | null {
    if (!token) return null;
    if (token.startsWith("$")) {
      const inner = token.slice(1);
      const defaultIdx = inner.indexOf(":-");
      const name = defaultIdx >= 0 ? inner.slice(0, defaultIdx) : inner;
      const fallback = defaultIdx >= 0 ? inner.slice(defaultIdx + 2) : "";
      const val = vars[name] ?? process.env[name];
      if (val && val.length > 0) return val;
      return fallback.length > 0 ? fallback : null;
    }

    if (token.startsWith("${") && token.endsWith("}")) {
      const inner = token.slice(2, -1);
      const defaultIdx = inner.indexOf(":-");
      const name = defaultIdx >= 0 ? inner.slice(0, defaultIdx) : inner;
      const fallback = defaultIdx >= 0 ? inner.slice(defaultIdx + 2) : "";
      const val = vars[name] ?? process.env[name];
      if (val && val.length > 0) return val;
      return fallback.length > 0 ? fallback : null;
    }

    return null;
  }
}
