import { checkDestructive } from "./parser/analyzer";
import { logAudit } from "./audit";
import { ToolInput } from "./types";

export async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (process.env.SHELLSHIELD_SKIP === "1") {
    process.exit(0);
  }

  if (args.includes("--init")) {
    const shell = process.env.SHELL?.split("/").pop() || "bash";
    if (shell === "zsh") {
      console.log(`
# ShellShield Zsh Integration
_shellshield_preexec() {
    # Skip if SHELLSHIELD_SKIP is set
    if [[ -n "$SHELLSHIELD_SKIP" ]]; then return 0; fi
    # Run shellshield check
    "${process.argv[1]}" --check "$1" || return $?
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec _shellshield_preexec
          `);
    } else {
      console.log(`
# ShellShield Bash Integration
_shellshield_bash_preexec() {
    if [[ -n "$SHELLSHIELD_SKIP" ]]; then return 0; fi
    "${process.argv[1]}" --check "$BASH_COMMAND" || return $?
}
trap '_shellshield_bash_preexec' DEBUG
          `);
    }
    process.exit(0);
  }

  if (args.includes("--check")) {
    const cmdIdx = args.indexOf("--check");
    const command = args[cmdIdx + 1];
    if (!command) process.exit(0);

    const result = checkDestructive(command);
    if (result.blocked) {
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
  console.error(
    `🛡️  ShellShield BLOCKED: ${reason}\n` +
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
      `ACTION REQUIRED: ${suggestion}\n` +
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
      `Bypass: SHELLSHIELD_SKIP=1 <command>\n` +
      `ShellShield - Keeping your terminal safe.`
  );
}
