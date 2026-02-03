import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";
import { isOperator, ParsedEntry } from "../types";
import { checkPipeToShell } from "../pipe-checks";
import { checkDownloadAndExec } from "../analyzer"; // Circular dependency? Need to move logic or refactor
import { checkBlockedCommand, checkFindCommand } from "../command-checks";
import { checkSubshellCommand } from "../subshell";
import { checkDestructive } from "../analyzer"; // Recursion needs careful handling
import { SHELL_COMMANDS } from "../../constants";
import { isSensitivePath } from "../../security/paths";

// We need to move checkDownloadAndExec out of analyzer.ts to avoid circular deps
// or duplicate it here. Since I am refactoring analyzer.ts anyway, I will move it to a helper.

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

  check(context: RuleContext): BlockResult | null {
    const { tokens, config, depth } = context;
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
        if (entry.includes("=") && !entry.startsWith("-")) {
          const [key, ...valParts] = entry.split("=");
          if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
            vars[key] = valParts.join("=");
          }
        }

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
        const remaining = tokens.slice(i + 1);
        const args = remaining.filter((item) => typeof item === "string") as string[];
        const pipeCheck = checkPipeToShell(args, remaining, config.trustedDomains);
        if (pipeCheck) return pipeCheck;

        // checkDownloadAndExec logic will be imported or implemented here
        const downloadExecCheck = this.checkDownloadAndExec(remaining, args);
        if (downloadExecCheck) return downloadExecCheck;
      }

      if (normalizedEntry === "bash" || normalizedEntry === "sh" || normalizedEntry === "zsh") {
        const remaining = tokens.slice(i + 1);
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
      if (cmdName.startsWith("$")) {
        const varName = cmdName.slice(1);
        resolvedCmd = (vars[varName] || cmdName).split("/").pop()?.toLowerCase() ?? "";
      }

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
        const remaining = tokens.slice(i + 1);
        const findCheck = checkFindCommand(remaining, config.blocked);
        if (findCheck) return findCheck;
      }

      if (SHELL_COMMANDS.has(resolvedCmd)) {
        const subshellResult = checkSubshellCommand(tokens, i + 1, (subshellCmd) => {
          // Recursive call back to main analyzer
          // Since we can't easily import checkDestructive due to cycles, 
          // we might need to rely on the fact that subshell.ts calls the callback provided.
          // In the real implementation, we pass checkDestructive bound or imported.
          return checkDestructive(subshellCmd, depth + 1, config);
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
}
