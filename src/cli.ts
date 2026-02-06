import { checkDestructive } from "./parser/analyzer";
import { logAudit } from "./audit";
import { getConfiguration } from "./config";
import { ToolInput } from "./types";
import { createInterface } from "node:readline";
import { printStats } from "./stats";
import { formatBlockedMessage } from "./ui/terminal";
import { writeShellContextSnapshot, parseTypeOutput, ShellContextSnapshot } from "./shell-context";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { scoreUrlRisk } from "./security/validators";
import { parse } from "shell-quote";

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

  const doctorHeader = "ShellShield Doctor";
  const doctorSeparator = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
  console.log(doctorHeader);
  console.log(doctorSeparator);
  console.log(`Shell: ${shell || "(unknown)"}`);
  console.log(`Mode: ${process.env.SHELLSHIELD_MODE || "(default)"}`);
  console.log("\nSafer delete command:");
  if (hasTrashPut) {
    console.log("- trash-put (recommended)");
  } else if (hasTrash) {
    console.log("- trash");
  } else if (hasGioTrash) {
    console.log("- gio trash");
  } else {
    console.log("- (none found) install trash-cli or use gio trash");
  }

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

function hasBypassPrefix(command: string): boolean {
  try {
    const tokens = parse(command) as Array<string | { op: string }>;
    let bypass = false;

    for (const token of tokens) {
      if (typeof token !== "string") {
        break;
      }

      if (token.includes("=")) {
        const [key, value] = token.split("=", 2);
        if (key === "SHELLSHIELD_SKIP" && value === "1") {
          bypass = true;
        }
        continue;
      }

      break;
    }

    return bypass;
  } catch {
    return false;
  }
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
    const promptMsg = `\n⚠️  ShellShield ALERT: ${reason}\n   Command: ${command}\n   Are you sure you want to execute this? [y/N] `;
    rl.question(
      promptMsg,
      (answer) => {
        rl.close();
        const lower = answer.toLowerCase();
        resolve(lower === "y" || lower === "yes");
      }
    );
  });
}

async function checkAndAuditCommand(command: string, config: any, source: "check" | "paste" | "stdin"): Promise<boolean> {
  const result = checkDestructive(command);
  if (result.blocked) {
    if (config?.mode === "permissive") {
      const warningHeader = `⚠️  ShellShield WARNING: Command '${command}' would be blocked in enforce mode.`;
      console.error(
        `${warningHeader}\n` +
          `Reason: ${result.reason}\n` +
          `Suggestion: ${result.suggestion}`
      );
      logAudit(command, { ...result, blocked: false }, { source, mode: config?.mode, threshold: config?.threshold, decision: "warn" });
      return true;
    }

    if (config?.mode === "interactive") {
      const confirmed = await promptConfirmation(command, result.reason);
      if (confirmed) {
        logAudit(command, { ...result, blocked: false }, { source, mode: config?.mode, threshold: config?.threshold, decision: "approved" });
        const msg = "Approved. Command will execute.";
        const tty = process.stderr.isTTY;
        console.error(tty ? `\x1b[32m${msg}\x1b[0m` : msg);
        return true;
      }
    }

    logAudit(command, result, { source, mode: config?.mode, threshold: config?.threshold, decision: "blocked" });
    showBlockedMessage(result.reason, result.suggestion);
    return false;
  }

  logAudit(command, result, { source, mode: config?.mode, threshold: config?.threshold, decision: "allowed" });
  return true;
}

async function handleCheck(args: string[], config: any): Promise<void> {
  const cmdIdx = args.indexOf("--check");
  const command = args[cmdIdx + 1];
  if (!command) process.exit(0);

  if (hasBypassPrefix(command)) {
    process.exit(0);
  }

  const ok = await checkAndAuditCommand(command, config, "check");
  process.exit(ok ? 0 : 2);
}

async function handlePaste(config: any): Promise<void> {
  try {
    const input = await Bun.stdin.text();
    if (!input) process.exit(0);

    const lines = input.split(/\r?\n/);
    for (const line of lines) {
      const command = line.trim();
      if (!command || hasBypassPrefix(command)) continue;

      const ok = await checkAndAuditCommand(command, config, "paste");
      if (!ok) process.exit(2);
    }

    process.exit(0);
  } catch (error) {
    if (process.env.DEBUG) console.error(error);
    process.exit(0);
  }
}

function handleSnapshot(args: string[], config: any): void {
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

function handleScore(args: string[], config: any): void {
  const idx = args.indexOf("--score");
  const url = args[idx + 1];
  if (!url) {
    console.error("Usage: shellshield --score <url>");
    process.exit(1);
  }
  const result = scoreUrlRisk(url, config.trustedDomains);
  const json = args.includes("--json");
  if (json) {
    console.log(JSON.stringify(result));
  } else {
    console.log(`Score: ${result.score}/100`);
    console.log(`Trusted: ${result.trusted ? "yes" : "no"}`);
    if (result.reasons.length > 0) {
      console.log("Reasons:");
      for (const reason of result.reasons) {
        console.log(`- ${reason}`);
      }
    }
  }
  process.exit(0);
}

import { SHELL_TEMPLATES } from "./integrations/templates";

function handleInit(): void {
  const shellPath = process.env.SHELL || "";
  const fallbackShell =
    !shellPath && (process.env.PSModulePath || process.env.ComSpec) ? "powershell" : "bash";
  const shellNameRaw = shellPath.split(/[\\/]/).pop() || fallbackShell;
  const shellName = shellNameRaw.replace(/\.exe$/i, "").toLowerCase();

  let templateKey = "bash";
  if (shellName === "zsh") templateKey = "zsh";
  else if (shellName === "fish") templateKey = "fish";
  else if (shellName === "pwsh" || shellName === "powershell") templateKey = "powershell";

  const template = SHELL_TEMPLATES[templateKey] || SHELL_TEMPLATES.bash;
  console.log(template.replaceAll("{{CLI_PATH}}", process.argv[1]));
  process.exit(0);
}

async function handleStdin(config: any): Promise<void> {
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

    if (!command || hasBypassPrefix(command)) {
      process.exit(0);
    }

    const ok = await checkAndAuditCommand(command, config, "stdin");
    process.exit(ok ? 0 : 2);
  } catch (error) {
    if (process.env.DEBUG) console.error(error);
    process.exit(0);
  }
}

export async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const config = getConfiguration();

  if (process.env.SHELLSHIELD_SKIP === "1") {
    process.exit(0);
  }

  if (args.includes("--init")) {
    handleInit();
  }

  if (args.includes("--stats")) {
    printStats();
    process.exit(0);
  }

  if (args.includes("--doctor")) {
    printDoctor();
    process.exit(0);
  }

  if (args.includes("--score")) {
    handleScore(args, config);
  }

  if (args.includes("--snapshot")) {
    handleSnapshot(args, config);
  }

  if (args.includes("--paste")) {
    await handlePaste(config);
  }

  if (args.includes("--check")) {
    await handleCheck(args, config);
  }

  await handleStdin(config);
}


function showBlockedMessage(reason: string, suggestion: string) {
  console.error(formatBlockedMessage(reason, suggestion, process.stderr.isTTY));
}
