import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";
import { isOperator, ParsedEntry } from "../types";
import { checkPipeToShell } from "../pipe-checks";
import { checkBlockedCommand, checkFindCommand } from "../command-checks";
import { checkSubshellCommand } from "../subshell";
import { SHELL_COMMANDS } from "../../constants";
import { isSensitivePath } from "../../security/paths";
import { getShellContextEntry, findBlockedTokenInShellContext } from "../../shell-context";
import { normalizeCommandName, resolveVariable } from "../utils";

export class CoreAstRule implements SecurityRule {
  readonly name = "CoreAstRule";
  readonly phase = "post" as const;

  check(context: RuleContext): BlockResult | null {
    const { tokens, config, depth, recursiveCheck } = context;
    const vars: Record<string, string> = {};
    let nextMustBeCommand = true;

    let i = 0;
    while (i < tokens.length) {
      const entry = tokens[i];

      if (isOperator(entry)) {
        const opResult = this.handleOperator(entry, tokens[i + 1]);
        if (opResult) return opResult;
        nextMustBeCommand = true;
        i++;
        continue;
      }

      if (typeof entry !== "string") {
        i++;
        continue;
      }

      if (!nextMustBeCommand) {
        this.checkEnvironmentVariable(entry, vars);
        const pathCheck = this.checkSensitivePathWrite(entry, tokens, i);
        if (pathCheck) return pathCheck;
        i++;
        continue;
      }

      nextMustBeCommand = false;
      if (this.checkEnvironmentVariable(entry, vars)) {
        nextMustBeCommand = true;
        i++;
        continue;
      }

      const normalizedEntry = entry.toLowerCase();

      const curlCheck = this.checkCurlWget(normalizedEntry, tokens, i, config);
      if (curlCheck) return curlCheck;

      const subCheck = this.checkBashSubshells(normalizedEntry, tokens, i);
      if (subCheck) return subCheck;

      if (this.isCommandPrefix(normalizedEntry)) {
        nextMustBeCommand = true;
        i++;
        continue;
      }

      if (normalizedEntry === "git" && this.isGitRm(tokens[i + 1])) {
        i += 2;
        continue;
      }

      const commandResult = this.handleCommand(entry, i, context, vars);
      if (commandResult) return commandResult;

      i++;
    }

    return null;
  }

  private handleOperator(opEntry: { op: string }, nextEntry: ParsedEntry | undefined): BlockResult | null {
    if (opEntry.op === "<(") {
      if (typeof nextEntry === "string" && (nextEntry === "curl" || nextEntry === "wget")) {
        return {
          blocked: true,
          reason: "PROCESS SUBSTITUTION DETECTED",
          suggestion: "Executing remote scripts via process substitution is dangerous.",
        };
      }
    }
    return null;
  }

  private isCommandPrefix(entry: string): boolean {
    return ["sudo", "xargs", "command", "env"].includes(entry);
  }

  private isGitRm(nextEntry: ParsedEntry | undefined): boolean {
    return typeof nextEntry === "string" && nextEntry.toLowerCase() === "rm";
  }

  private handleCommand(entry: string, i: number, context: RuleContext, vars: Record<string, string>): BlockResult | null {
    const { tokens, config, depth, recursiveCheck } = context;
    const resolvedCmd = this.resolveCmdName(entry, vars);
    
    const ctxCheck = this.checkShellContext(resolvedCmd, config);
    if (ctxCheck) return ctxCheck;

    if (config.allowed.has(resolvedCmd)) return null;

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

    return null;
  }

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

  private checkBashSubshells(normalizedEntry: string, tokens: ParsedEntry[], i: number): BlockResult | null {
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

  private resolveCmdName(entry: string, vars: Record<string, string>): string {
    const name = normalizeCommandName(entry);
    const resolvedVar = resolveVariable(entry, vars);
    if (resolvedVar) {
      return normalizeCommandName(resolvedVar);
    }
    return name;
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
}
