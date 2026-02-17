import { SecurityRule, RuleContext } from "./interface";
import { BlockResult } from "../../types";
import { isOperator, ParsedEntry } from "../types";
import { checkPipeToShell } from "../pipe-checks";
import { checkBlockedCommand, checkFindCommand } from "../command-checks";
import { checkSubshellCommand } from "../subshell";
import { SHELL_COMMANDS } from "../../constants";
import { isSensitivePath } from "../../security/paths";
import {
  getShellContextEntry,
  findBlockedTokenInShellContext,
} from "../../shell-context";
import { normalizeCommandName, resolveVariable } from "../utils";

const CONTROL_OPERATORS = new Set(["&&", "||", ";", "&"]);
const COMMAND_BOUNDARY_OPERATORS = new Set([
  ...CONTROL_OPERATORS,
  "|",
  "|&",
]);
const REDIRECTION_OPERATORS = new Set([
  ">",
  ">>",
  "<",
  "<<",
  "<<<",
  "<>",
  "1>",
  "1>>",
  "2>",
  "2>>",
  "&>",
  ">&",
  "<&",
]);
const DANGEROUS_DOWNLOAD_EXECUTORS = new Set([
  ...SHELL_COMMANDS,
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
  "exec",
  "chmod",
]);

export class CoreAstRule implements SecurityRule {
  readonly name = "CoreAstRule";
  readonly phase = "post" as const;

  check(context: RuleContext): BlockResult | null {
    const { tokens, config } = context;
    const vars: Record<string, string> = {};
    let nextMustBeCommand = true;

    let i = 0;
    while (i < tokens.length) {
      const entry = tokens[i];

      if (isOperator(entry)) {
        const opResult = this.handleOperator(entry, tokens[i + 1], vars);
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

      const resolvedEntry = resolveVariable(entry, vars) || entry;
      const normalizedEntry = normalizeCommandName(resolvedEntry);
      const remaining = tokens.slice(i + 1);
      const commandSegment = this.sliceUntilOperators(
        remaining,
        CONTROL_OPERATORS
      );
      const currentCommandEntries = this.sliceUntilOperators(
        commandSegment,
        COMMAND_BOUNDARY_OPERATORS
      );

      const curlCheck = this.handleCurlWget(
        normalizedEntry,
        remaining,
        commandSegment,
        currentCommandEntries,
        config,
        vars
      );
      if (curlCheck) return curlCheck;

      const subCheck = this.handleBashSubshells(
        normalizedEntry,
        commandSegment,
        vars
      );
      if (subCheck) return subCheck;

      if (this.isCommandPrefix(normalizedEntry)) {
        nextMustBeCommand = true;
        i++;
        continue;
      }

      if (normalizedEntry === "git" && this.isGitRm(currentCommandEntries[0])) {
        i += 2;
        continue;
      }

      const commandResult = this.handleCommand(
        resolvedEntry,
        currentCommandEntries,
        context,
        vars
      );
      if (commandResult) return commandResult;

      i++;
    }

    return null;
  }

  private handleOperator(
    opEntry: { op: string },
    nextEntry: ParsedEntry | undefined,
    vars: Record<string, string>
  ): BlockResult | null {
    if (opEntry.op === "<(") {
      if (typeof nextEntry === "string") {
        const normalizedNext = normalizeCommandName(
          resolveVariable(nextEntry, vars)
        );
        if (normalizedNext === "curl" || normalizedNext === "wget") {
          return {
            blocked: true,
            reason: "PROCESS SUBSTITUTION DETECTED",
            suggestion:
              "Executing remote scripts via process substitution is dangerous.",
          };
        }
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

  private sliceUntilOperators(
    entries: ParsedEntry[],
    stopOperators: Set<string>
  ): ParsedEntry[] {
    const slice: ParsedEntry[] = [];
    for (const entry of entries) {
      if (isOperator(entry) && stopOperators.has(entry.op)) break;
      slice.push(entry);
    }
    return slice;
  }

  private getCommandArgs(entries: ParsedEntry[]): string[] {
    const args: string[] = [];
    let skipNextForRedirection = false;

    for (const entry of entries) {
      if (isOperator(entry)) {
        skipNextForRedirection = REDIRECTION_OPERATORS.has(entry.op);
        continue;
      }
      if (typeof entry !== "string") continue;
      if (skipNextForRedirection) {
        skipNextForRedirection = false;
        continue;
      }
      args.push(entry);
    }

    return args;
  }

  private handleCommand(
    entry: string,
    commandEntries: ParsedEntry[],
    context: RuleContext,
    vars: Record<string, string>
  ): BlockResult | null {
    const { config, depth, recursiveCheck } = context;
    const resolvedCmd = this.resolveCmdName(entry, vars);

    const ctxCheck = this.checkShellContext(resolvedCmd, config);
    if (ctxCheck) return ctxCheck;

    if (config.allowed.has(resolvedCmd)) return null;

    const args = this.getCommandArgs(commandEntries);
    const blockedCheck = checkBlockedCommand(resolvedCmd, args, {
      blocked: config.blocked,
      threshold: config.threshold,
    });
    if (blockedCheck) return blockedCheck;

    if (resolvedCmd === "find") {
      const findCheck = checkFindCommand(commandEntries, config.blocked);
      if (findCheck) return findCheck;
    }

    if (SHELL_COMMANDS.has(resolvedCmd)) {
      const subshellResult = checkSubshellCommand(commandEntries, 0, (subshellCmd) => {
        return recursiveCheck(subshellCmd, depth + 1);
      });
      if (subshellResult?.blocked) return subshellResult;
    }

    return null;
  }

  private checkEnvironmentVariable(
    entry: string,
    vars: Record<string, string>
  ): boolean {
    if (entry.includes("=") && !entry.startsWith("-")) {
      const [key, ...valParts] = entry.split("=");
      if (/^\w+$/.test(key)) {
        vars[key] = valParts.join("=");
        return true;
      }
    }
    return false;
  }

  private checkSensitivePathWrite(
    entry: string,
    tokens: ParsedEntry[],
    i: number
  ): BlockResult | null {
    let outputPath: string | null = null;

    if (
      (entry === "-o" ||
        entry === "-O" ||
        entry === "--output" ||
        entry === "--output-document") &&
      i + 1 < tokens.length
    ) {
      const next = tokens[i + 1];
      if (typeof next === "string") outputPath = next;
    } else if (entry.startsWith("--output=")) {
      outputPath = entry.slice("--output=".length);
    } else if (entry.startsWith("--output-document=")) {
      outputPath = entry.slice("--output-document=".length);
    } else if (entry.startsWith("-o") && entry.length > 2) {
      outputPath = entry.slice(2);
    } else if (entry.startsWith("-O") && entry.length > 2) {
      outputPath = entry.slice(2);
    }

    if (outputPath && isSensitivePath(outputPath)) {
      return {
        blocked: true,
        reason: "SENSITIVE PATH TARGETED",
        suggestion: `Command is attempting to write directly to a critical configuration file: ${outputPath}`,
      };
    }

    return null;
  }

  private handleCurlWget(
    normalizedEntry: string,
    remaining: ParsedEntry[],
    commandSegment: ParsedEntry[],
    currentCommandEntries: ParsedEntry[],
    config: RuleContext["config"],
    vars: Record<string, string>
  ): BlockResult | null {
    if (normalizedEntry !== "curl" && normalizedEntry !== "wget") return null;

    const currentArgs = this.getCommandArgs(currentCommandEntries);
    const pipeCheck = checkPipeToShell(
      currentArgs,
      commandSegment,
      config.trustedDomains
    );
    if (pipeCheck) return pipeCheck;

    return this.checkDownloadAndExec(
      remaining,
      currentArgs,
      normalizedEntry,
      vars
    );
  }

  private handleBashSubshells(
    normalizedEntry: string,
    commandSegment: ParsedEntry[],
    vars: Record<string, string>
  ): BlockResult | null {
    if (
      normalizedEntry === "bash" ||
      normalizedEntry === "sh" ||
      normalizedEntry === "zsh"
    ) {
      const hasSubstitution = commandSegment.some((item) => {
        if (typeof item !== "string") return false;
        const resolved = resolveVariable(item, vars);
        return (
          resolved.includes("<(curl") ||
          resolved.includes("<(wget") ||
          resolved.includes("< <(curl") ||
          resolved.includes("< <(wget")
        );
      });
      if (hasSubstitution) {
        return {
          blocked: true,
          reason: "PROCESS SUBSTITUTION DETECTED",
          suggestion:
            "Executing remote scripts via process substitution is dangerous.",
        };
      }
    }
    return null;
  }

  private resolveCmdName(entry: string, vars: Record<string, string>): string {
    const expanded = resolveVariable(entry, vars);
    return normalizeCommandName(expanded);
  }

  private checkShellContext(
    resolvedCmd: string,
    config: RuleContext["config"]
  ): BlockResult | null {
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

  private checkDownloadAndExec(
    remaining: ParsedEntry[],
    commandArgs: string[],
    downloader: "curl" | "wget",
    vars: Record<string, string>
  ): BlockResult | null {
    const downloadTargets = this.extractDownloadTargets(
      commandArgs,
      downloader,
      vars
    );
    if (downloadTargets.length === 0) return null;

    const opIdx = remaining.findIndex(
      (entry) => isOperator(entry) && CONTROL_OPERATORS.has(entry.op)
    );
    if (opIdx === -1) return null;

    const nextCommand = this.extractNextCommand(remaining.slice(opIdx + 1), vars);
    if (!nextCommand) return null;

    if (this.referencesAnyTarget(nextCommand.token, downloadTargets)) {
      return {
        blocked: true,
        reason: "DOWNLOAD-AND-EXEC DETECTED",
        suggestion:
          "Downloading and executing a script in one command is dangerous. Review the script first.",
      };
    }

    if (!DANGEROUS_DOWNLOAD_EXECUTORS.has(nextCommand.name)) return null;

    if (nextCommand.args.some((arg) => this.referencesAnyTarget(arg, downloadTargets))) {
      return {
        blocked: true,
        reason: "DOWNLOAD-AND-EXEC DETECTED",
        suggestion:
          "Downloading and executing a script in one command is dangerous. Review the script first.",
      };
    }

    return null;
  }

  private extractDownloadTargets(
    commandArgs: string[],
    downloader: "curl" | "wget",
    vars: Record<string, string>
  ): string[] {
    const resolvedArgs = commandArgs.map((arg) => resolveVariable(arg, vars));
    const targets = new Set<string>();
    let hasExplicitOutput = false;
    let remoteNameRequested = false;

    for (let i = 0; i < resolvedArgs.length; i++) {
      const arg = resolvedArgs[i];
      const next = resolvedArgs[i + 1];

      if (!arg) continue;

      const explicit = this.extractExplicitOutputPath(arg, next, downloader);
      if (explicit.handled) {
        if (explicit.path && this.isFilesystemTarget(explicit.path)) {
          hasExplicitOutput = true;
          targets.add(explicit.path);
        } else if (explicit.path) {
          hasExplicitOutput = true;
        }
        if (explicit.consumeNext) i++;
        continue;
      }

      if (downloader === "curl" && this.isRemoteNameRequestedForCurl(arg)) {
        remoteNameRequested = true;
      }
    }

    const urlBasenames = this.getUrlBasenames(resolvedArgs);
    if (downloader === "wget" && !hasExplicitOutput) {
      for (const name of urlBasenames) targets.add(name);
    }
    if (downloader === "curl" && remoteNameRequested) {
      for (const name of urlBasenames) targets.add(name);
    }

    return [...targets];
  }

  private extractExplicitOutputPath(
    arg: string,
    next: string | undefined,
    downloader: "curl" | "wget"
  ): { handled: boolean; consumeNext: boolean; path?: string } {
    if (arg === "-o" || arg === "--output") {
      return { handled: true, consumeNext: true, path: next };
    }
    if (arg.startsWith("-o") && arg.length > 2) {
      return { handled: true, consumeNext: false, path: arg.slice(2) };
    }
    if (arg.startsWith("--output=")) {
      return {
        handled: true,
        consumeNext: false,
        path: arg.slice("--output=".length),
      };
    }

    if (downloader === "wget") {
      if (arg === "-O" || arg === "--output-document") {
        return { handled: true, consumeNext: true, path: next };
      }
      if (arg.startsWith("-O") && arg.length > 2) {
        return { handled: true, consumeNext: false, path: arg.slice(2) };
      }
      if (arg.startsWith("--output-document=")) {
        return {
          handled: true,
          consumeNext: false,
          path: arg.slice("--output-document=".length),
        };
      }
    }

    return { handled: false, consumeNext: false };
  }

  private isRemoteNameRequestedForCurl(arg: string): boolean {
    if (arg === "-O" || arg === "--remote-name") return true;
    if (/^-[A-Za-z]+$/.test(arg) && arg.includes("O")) return true;
    return false;
  }

  private getUrlBasenames(args: string[]): string[] {
    const names = new Set<string>();
    for (const arg of args) {
      if (!this.looksLikeHttpUrl(arg)) continue;
      try {
        const parsed = new URL(arg);
        const normalizedPath = parsed.pathname.replace(/\/+$/, "");
        const fileName = normalizedPath.split("/").pop() || "";
        if (!fileName) continue;
        names.add(decodeURIComponent(fileName));
      } catch {
        continue;
      }
    }
    return [...names];
  }

  private extractNextCommand(
    entries: ParsedEntry[],
    vars: Record<string, string>
  ): { token: string; name: string; args: string[] } | null {
    const segment = this.sliceUntilOperators(entries, CONTROL_OPERATORS);
    const strings = this.getCommandArgs(segment).map((s) => resolveVariable(s, vars));
    if (strings.length === 0) return null;

    for (let i = 0; i < strings.length; i++) {
      const token = strings[i];
      if (/^\w+=/.test(token)) continue;
      const normalized = normalizeCommandName(token);
      if (this.isCommandPrefix(normalized)) continue;
      return { token, name: normalized, args: strings.slice(i + 1) };
    }

    return null;
  }

  private referencesAnyTarget(value: string, targets: string[]): boolean {
    if (!value || this.looksLikeHttpUrl(value)) return false;
    const normalizedValue = this.normalizePathLike(value);

    for (const target of targets) {
      const normalizedTarget = this.normalizePathLike(target);
      if (!normalizedTarget) continue;

      if (normalizedValue === normalizedTarget) return true;

      const valueBase = this.getPathBase(normalizedValue);
      const targetBase = this.getPathBase(normalizedTarget);
      if (valueBase && targetBase && valueBase === targetBase) return true;
    }

    return false;
  }

  private isFilesystemTarget(path: string): boolean {
    const normalized = this.normalizePathLike(path);
    return normalized.length > 0 && normalized !== "-" && normalized !== "/dev/stdout";
  }

  private normalizePathLike(value: string): string {
    return value
      .trim()
      .replace(/^['"]|['"]$/g, "")
      .replace(/\\/g, "/")
      .replace(/^\.\/+/, "")
      .replace(/\/+$/, "");
  }

  private getPathBase(value: string): string {
    const normalized = value.replace(/\\/g, "/");
    return normalized.split("/").pop() || normalized;
  }

  private looksLikeHttpUrl(value: string): boolean {
    return /^https?:\/\//i.test(value);
  }
}
