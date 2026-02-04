import { checkDestructive } from "./parser/analyzer";
import { logAudit } from "./audit";
import { getConfiguration } from "./config";
import { ToolInput } from "./types";
import { createInterface } from "readline";
import { printStats } from "./stats";

async function promptConfirmation(command: string, reason: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;

  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise((resolve) => {
    rl.question(
      `\n⚠️  ShellShield ALERT: ${reason}\n` +
      `   Command: ${command}\n` +
      `   Are you sure you want to execute this? [y/N] `,
      (answer) => {
        rl.close();
        resolve(answer.toLowerCase() === "y" || answer.toLowerCase() === "yes");
      }
    );
  });
}

export async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const config = getConfiguration();

  if (process.env.SHELLSHIELD_SKIP === "1") {
    process.exit(0);
  }

  if (args.includes("--init")) {
    const shell = process.env.SHELL?.split("/").pop() || "bash";
    if (shell === "zsh") {
      console.log(`
# ShellShield Zsh Integration
_shellshield_accept_line() {
    if [[ -n "$SHELLSHIELD_SKIP" ]]; then
        zle .accept-line
        return
    fi
    if command -v bun >/dev/null 2>&1; then
        bun run "${process.argv[1]}" --check "$BUFFER" || return $?
    fi
    zle .accept-line
}
zle -N accept-line _shellshield_accept_line
autoload -Uz add-zsh-hook
add-zsh-hook -d preexec _shellshield_preexec 2>/dev/null
unfunction _shellshield_preexec 2>/dev/null
          `);
    } else {
      console.log(`
# ShellShield Bash Integration
_shellshield_bash_preexec() {
    if [[ -n "$SHELLSHIELD_SKIP" ]]; then return 0; fi
    if command -v bun >/dev/null 2>&1; then
        bun run "${process.argv[1]}" --check "$BASH_COMMAND" || return $?
    fi
}
trap '_shellshield_bash_preexec' DEBUG
          `);
    }
    process.exit(0);
  }

  if (args.includes("--stats")) {
    printStats();
    process.exit(0);
  }

  if (args.includes("--check")) {
    const cmdIdx = args.indexOf("--check");
    const command = args[cmdIdx + 1];
    if (!command) process.exit(0);

    const result = checkDestructive(command);
    if (result.blocked) {
      if (config.mode === "permissive") {
        console.error(
          `⚠️  ShellShield WARNING: Command '${command}' would be blocked in enforce mode.\n` +
            `Reason: ${result.reason}\n` +
            `Suggestion: ${result.suggestion}`
        );
        logAudit(command, { ...result, blocked: false });
        process.exit(0);
      }
      if (config.mode === "interactive") {
        const confirmed = await promptConfirmation(command, result.reason);
        if (confirmed) {
           logAudit(command, { ...result, blocked: false });
           process.exit(0);
        }
      }

      showBlockedMessage(result.reason, result.suggestion);
      process.exit(2);
    }
    process.exit(0);
  }

  try {
    const input = await Bun.stdin.text();
    if (!input) process.exit(0);

    let command = "";
    try {
      const data: ToolInput = JSON.parse(input);
      command = data.tool_input?.command ?? "";
    } catch {
      command = input.trim();
    }

    if (!command) {
      process.exit(0);
    }

    const result = checkDestructive(command);
    logAudit(command, result);

    if (result.blocked) {
      if (config.mode === "permissive") {
        console.error(
          `⚠️  ShellShield WARNING: Command would be blocked in enforce mode.\n` +
            `Reason: ${result.reason}\n` +
            `Suggestion: ${result.suggestion}`
        );
        process.exit(0);
      }

      if (config.mode === "interactive") {
        const confirmed = await promptConfirmation(command, result.reason);
        if (confirmed) {
           logAudit(command, { ...result, blocked: false });
           process.exit(0);
        }
      }

      showBlockedMessage(result.reason, result.suggestion);
      process.exit(2);
    }

    process.exit(0);
  } catch (error) {
    if (process.env.DEBUG) console.error(error);
    process.exit(0);
  }
}


function showBlockedMessage(reason: string, suggestion: string) {
  const isTty = process.stderr.isTTY;
  const red = isTty ? "\x1b[31m" : "";
  const yellow = isTty ? "\x1b[33m" : "";
  const cyan = isTty ? "\x1b[36m" : "";
  const dim = isTty ? "\x1b[2m" : "";
  const gray = isTty ? "\x1b[90m" : "";
  const bold = isTty ? "\x1b[1m" : "";
  const reset = isTty ? "\x1b[0m" : "";
  const line = `${gray}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${reset}`;
  const highlightedSuggestion = suggestion.replace(
    /(\/[^\s"']+|[A-Za-z]:\\[^\s"']+)/g,
    `${cyan}$1${reset}`
  );
  console.error(
    `\n${red}🛡️ ${reset}ShellShield ${red}BLOCKED${reset}: ${reason}\n` +
      `${line}\n` +
      `${bold}${yellow}ACTION REQUIRED:${reset} ${highlightedSuggestion}\n` +
      `${line}\n` +
      `${dim}Bypass: SHELLSHIELD_SKIP=1 <command>${reset}\n` +
      `${dim}Hint:   set SHELLSHIELD_MODE=interactive for quick prompts${reset}\n` +
      `${dim}ShellShield - Keeping your terminal safe.${reset}`
  );
}
