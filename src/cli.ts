import { checkDestructive } from "./parser/analyzer";
import { logAudit } from "./audit";
import { getConfiguration } from "./config";
import { ToolInput } from "./types";
import { createInterface } from "readline";
import { printStats } from "./stats";
import { formatBlockedMessage } from "./ui/terminal";
import { writeShellContextSnapshot, parseTypeOutput, ShellContextSnapshot } from "./shell-context";
import { homedir } from "os";
import { resolve } from "path";

function runProbe(cmd: string[]): { ok: boolean; out: string } {
  try {
    const proc = Bun.spawnSync({
      cmd,
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
    });
    const out = (proc.stdout?.toString() ?? "") + (proc.stderr?.toString() ?? "");
    return { ok: proc.exitCode === 0, out: out.trim() };
  } catch {
    return { ok: false, out: "" };
  }
}

function printDoctor(): void {
  const shell = process.env.SHELL || "";
  const hasTrashPut = runProbe(["bash", "-lc", "command -v trash-put"]).ok;
  const hasTrash = runProbe(["bash", "-lc", "command -v trash"]).ok;
  const hasGioTrash = runProbe(["bash", "-lc", "command -v gio"]).ok;

  console.log("ShellShield Doctor");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`Shell: ${shell || "(unknown)"}`);
  console.log(`Mode: ${process.env.SHELLSHIELD_MODE || "(default)"}`);
  console.log("\nSafer delete command:");
  if (hasTrashPut) console.log("- trash-put (recommended)");
  else if (hasTrash) console.log("- trash");
  else if (hasGioTrash) console.log("- gio trash");
  else console.log("- (none found) install trash-cli or use gio trash");

  if (shell) {
    const typeRm = runProbe(["bash", "-lc", `${shell} -ic 'type rm 2>/dev/null'`]).out;
    if (typeRm) {
      console.log("\nShell context (rm):");
      console.log(typeRm.split("\n")[0]);
      console.log("Note: ShellShield analyzes the raw command; alias/function bodies may not be visible.");
    }
  }
}

function isSafeCommandName(name: string): boolean {
  return /^[A-Za-z0-9._+-]+$/.test(name);
}

function parseCsvArg(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function defaultSnapshotPath(): string {
  return resolve(homedir(), ".shellshield", "shell-context.json");
}

function printSnapshotHelp(): void {
  console.log("ShellShield Shell Context Snapshot");
  console.log("Usage:");
  console.log("  shellshield --snapshot [--out <path>] [--commands <csv>] [--shell <path>]");
  console.log("");
  console.log("Env:");
  console.log("  SHELLSHIELD_CONTEXT_PATH=<path>   Enable alias/function safety checks");
  console.log("");
  console.log("Example:");
  console.log("  shellshield --snapshot --out ~/.shellshield/shell-context.json --commands ls,rm,git");
}

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

  if (args.includes("--doctor")) {
    printDoctor();
    process.exit(0);
  }

  if (args.includes("--snapshot")) {
    if (args.includes("--help") || args.includes("-h")) {
      printSnapshotHelp();
      process.exit(0);
    }

    const outIdx = args.indexOf("--out");
    const outPath = outIdx !== -1 ? args[outIdx + 1] : "";
    const shellIdx = args.indexOf("--shell");
    const shellArg = shellIdx !== -1 ? args[shellIdx + 1] : "";
    const commandsIdx = args.indexOf("--commands");
    const commandsArg = commandsIdx !== -1 ? args[commandsIdx + 1] : "";

    const shell = (shellArg && shellArg.trim()) || process.env.SHELL || "/bin/bash";
    const safeShell = /^[A-Za-z0-9_./-]+$/.test(shell) ? shell : "/bin/bash";

    const common = ["ls", "rm", "mv", "cp", "cat", "grep", "find", "xargs", "git", "curl", "wget", "sh", "bash", "zsh"];
    const requested = parseCsvArg(commandsArg);
    const cmdList = (requested.length > 0 ? requested : [...config.blocked, ...common])
      .map((c) => c.trim())
      .filter((c) => isSafeCommandName(c));

    const uniq = Array.from(new Set(cmdList.map((c) => c.toLowerCase())));
    const entries: ShellContextSnapshot["entries"] = {};

    for (const cmd of uniq) {
      const probe = runProbe([safeShell, "-ic", `type ${cmd} 2>/dev/null`]);
      if (!probe.out) continue;
      entries[cmd] = parseTypeOutput(probe.out);
    }

    const snapshot: ShellContextSnapshot = {
      version: 1,
      generatedAt: new Date().toISOString(),
      shell: safeShell,
      entries,
    };

    const finalOut = outPath && outPath.trim().length > 0 ? outPath.trim() : defaultSnapshotPath();
    writeShellContextSnapshot(finalOut, snapshot);
    console.log(finalOut);
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
        logAudit(command, { ...result, blocked: false }, { source: "check", mode: config.mode, threshold: config.threshold, decision: "warn" });
        process.exit(0);
      }
      if (config.mode === "interactive") {
        const confirmed = await promptConfirmation(command, result.reason);
        if (confirmed) {
           logAudit(command, { ...result, blocked: false }, { source: "check", mode: config.mode, threshold: config.threshold, decision: "approved" });
           if (process.stderr.isTTY) {
             console.error("\x1b[32mApproved. Command will execute.\x1b[0m");
           } else {
             console.error("Approved. Command will execute.");
           }
           process.exit(0);
        }
        if (process.stderr.isTTY) {
          console.error("\x1b[90mCancelled by user.\x1b[0m");
        } else {
          console.error("Cancelled by user.");
        }
      }

      logAudit(command, result, { source: "check", mode: config.mode, threshold: config.threshold, decision: "blocked" });
      showBlockedMessage(result.reason, result.suggestion);
      process.exit(2);
    }
    logAudit(command, result, { source: "check", mode: config.mode, threshold: config.threshold, decision: "allowed" });
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

    if (result.blocked) {
      if (config.mode === "permissive") {
        console.error(
          `⚠️  ShellShield WARNING: Command would be blocked in enforce mode.\n` +
            `Reason: ${result.reason}\n` +
            `Suggestion: ${result.suggestion}`
        );
        logAudit(command, { ...result, blocked: false }, { source: "stdin", mode: config.mode, threshold: config.threshold, decision: "warn" });
        process.exit(0);
      }

      if (config.mode === "interactive") {
        const confirmed = await promptConfirmation(command, result.reason);
        if (confirmed) {
           logAudit(command, { ...result, blocked: false }, { source: "stdin", mode: config.mode, threshold: config.threshold, decision: "approved" });
           if (process.stderr.isTTY) {
             console.error("\x1b[32mApproved. Command will execute.\x1b[0m");
           } else {
             console.error("Approved. Command will execute.");
           }
           process.exit(0);
        }
        if (process.stderr.isTTY) {
          console.error("\x1b[90mCancelled by user.\x1b[0m");
        } else {
          console.error("Cancelled by user.");
        }
      }

      logAudit(command, result, { source: "stdin", mode: config.mode, threshold: config.threshold, decision: "blocked" });
      showBlockedMessage(result.reason, result.suggestion);
      process.exit(2);
    }

    logAudit(command, result, { source: "stdin", mode: config.mode, threshold: config.threshold, decision: "allowed" });
    process.exit(0);
  } catch (error) {
    if (process.env.DEBUG) console.error(error);
    process.exit(0);
  }
}


function showBlockedMessage(reason: string, suggestion: string) {
  console.error(formatBlockedMessage(reason, suggestion, process.stderr.isTTY));
}
