#!/usr/bin/env bun
import { parse } from "shell-quote";

/**
 * Block destructive file deletion commands and suggest using trash instead.
 * This is a OpenCode hook that runs on PreToolUse for Bash commands.
 */

interface ToolInput {
  tool_input?: {
    command?: string;
  };
}

const BLOCKED_COMMANDS = new Set(["rm", "shred", "unlink", "wipe", "srm"]);
const SHELL_COMMANDS = new Set(["sh", "bash", "zsh", "dash"]);

/**
 * Get configuration from environment variables.
 */
function getConfiguration() {
    const blocked = new Set(BLOCKED_COMMANDS);
    const allowed = new Set<string>();

    if (process.env.OPENCODE_BLOCK_COMMANDS) {
        process.env.OPENCODE_BLOCK_COMMANDS.split(",").forEach(cmd => blocked.add(cmd.trim().toLowerCase()));
    }

    if (process.env.OPENCODE_ALLOW_COMMANDS) {
        process.env.OPENCODE_ALLOW_COMMANDS.split(",").forEach(cmd => allowed.add(cmd.trim().toLowerCase()));
    }

    return { blocked, allowed };
}

interface BlockResult {
  blocked: boolean;
  suggestion?: string;
}

/**
 * Check if a command is destructive and return a suggestion if so.
 */
function checkDestructive(command: string, depth = 0): BlockResult {
  if (depth > 5) return { blocked: false };

  const { blocked: configBlocked, allowed: configAllowed } = getConfiguration();
  const vars: Record<string, string> = {};
  
  const entries = parse(command, (key) => {
      return vars[key] || `$${key}`;
  });
  
  let nextMustBeCommand = true;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    if (typeof entry !== "string") {
        if (typeof entry === "object" && "op" in entry) {
            nextMustBeCommand = true;
        }
        continue;
    }

    if (!nextMustBeCommand) {
        if (entry.includes("=") && !entry.startsWith("-")) {
            const [key, ...valParts] = entry.split("=");
            if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
                vars[key] = valParts.join("=");
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

    if (["sudo", "xargs", "command", "env"].includes(normalizedEntry)) {
      nextMustBeCommand = true;
      continue;
    }

    if (normalizedEntry === "git" && i + 1 < entries.length) {
      const next = entries[i + 1];
      if (typeof next === "string" && next.toLowerCase() === "rm") {
        i++;
        continue;
      }
    }

    const basename = entry.split("/").pop() ?? "";
    const cmdName = entry.startsWith("\\") ? entry.slice(1) : basename;

    let resolvedCmd = cmdName.toLowerCase();
    if (cmdName.startsWith("$")) {
        const varName = cmdName.slice(1);
        resolvedCmd = (vars[varName] || cmdName).split("/").pop()?.toLowerCase() ?? "";
    }

    if (configAllowed.has(resolvedCmd)) {
        continue;
    }

    if (configBlocked.has(resolvedCmd)) {
        let suggestion = "trash <files>";
        if (resolvedCmd === "rm") {
            const args = entries.slice(i + 1).filter(e => typeof e === "string") as string[];
            const nonFlags = args.filter(a => !a.startsWith("-"));
            if (nonFlags.length > 0) {
                suggestion = `trash ${nonFlags.join(" ")}`;
            }
        }
        return { blocked: true, suggestion };
    }

    if (resolvedCmd === "find") {
        const remaining = entries.slice(i + 1);
        if (remaining.some(e => typeof e === "string" && e.toLowerCase() === "-delete")) {
            return { blocked: true, suggestion: "trash <files>" };
        }
        const execIdx = remaining.findIndex(e => typeof e === "string" && e.toLowerCase() === "-exec");
        if (execIdx !== -1 && execIdx + 1 < remaining.length) {
            const execCmd = remaining[execIdx + 1];
            if (typeof execCmd === "string" && configBlocked.has(execCmd.split("/").pop()?.toLowerCase() ?? "")) {
                return { blocked: true, suggestion: "trash <files>" };
            }
        }
    }

    if (resolvedCmd === "dd") {
        const remaining = entries.slice(i + 1);
        if (remaining.some(e => typeof e === "string" && e.toLowerCase().startsWith("of="))) {
            return { blocked: true, suggestion: "be careful with dd of=" };
        }
    }

    if (SHELL_COMMANDS.has(resolvedCmd)) {
        const cIdx = entries.slice(i + 1).findIndex(e => typeof e === "string" && e === "-c");
        if (cIdx !== -1 && i + 1 + cIdx + 1 < entries.length) {
            const subshellCmd = entries[i + 1 + cIdx + 1];
            if (typeof subshellCmd === "string") {
                const result = checkDestructive(subshellCmd, depth + 1);
                if (result.blocked) return result;
            }
        }
    }
  }

  return { blocked: false };
}

async function main(): Promise<void> {
  try {
    const input = await Bun.stdin.text();
    if (!input) process.exit(0);
    
    const data: ToolInput = JSON.parse(input);
    const command = data.tool_input?.command ?? "";

    if (!command) {
      process.exit(0);
    }

    const result = checkDestructive(command);

    if (result.blocked) {
      console.error(
        `🛡️  ShellShield BLOCKED: Destructive command detected.\n` +
        `Instead of deleting permanently, use 'trash':\n` +
        `  ${result.suggestion ?? "trash <file>"}\n\n` +
        `ShellShield helps you keep your files safe. To bypass this, see the documentation.`
      );
      process.exit(2);
    }

    process.exit(0);
  } catch {
    process.exit(0);
  }
}

main();
