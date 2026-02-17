import { checkDestructive } from "./parser/analyzer";
import { logAudit } from "./audit";
import { getConfiguration } from "./config";
import { ToolInput, Config } from "./types";
import { createInterface } from "node:readline";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { printStats } from "./stats";
import { formatBlockedMessage } from "./ui/terminal";
import { writeShellContextSnapshot, parseTypeOutput, ShellContextSnapshot } from "./shell-context";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scoreUrlRisk } from "./security/validators";
import { isBypassEnabled, hasBypassPrefix } from "./utils/bypass";
import { SHELL_TEMPLATES } from "./integrations/templates";
import { createHash } from "node:crypto";

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

function defaultSnapshotPath(): string {
  return resolve(homedir(), ".shellshield", "shell-context.json");
}

interface InitCommandContext {
  invokePosix: string;
  invokeFish: string;
  invokePwsh: string;
  availablePosix: string;
  availableFish: string;
  availablePwsh: string;
}

type ShellShieldMode = Config["mode"];
const MODE_CHOICES: ShellShieldMode[] = ["enforce", "interactive", "permissive"];

function isValidMode(value: string): value is ShellShieldMode {
  return MODE_CHOICES.includes(value as ShellShieldMode);
}

interface AuditLogEntry {
  id?: string;
  timestamp?: string;
  command?: string;
  blocked?: boolean;
  decision?: "blocked" | "allowed" | "warn" | "approved";
  mode?: ShellShieldMode;
  source?: "check" | "paste" | "stdin" | "run";
  rule?: string;
  reason?: string;
  suggestion?: string;
}

interface ScriptFinding {
  line: number;
  command: string;
  reason: string;
  suggestion: string;
  rule?: string;
}

function quotePosix(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function quotePwsh(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function looksLikeBundledPath(path: string): boolean {
  return path.includes("/$bunfs/") || path.includes("\\$bunfs\\");
}

function resolveInitCommandContext(): InitCommandContext {
  const scriptPath = process.argv[1] || "";

  if (scriptPath && looksLikeBundledPath(scriptPath)) {
    const executable = resolve(process.cwd(), process.execPath || process.argv[0]);
    const posixPath = quotePosix(executable);
    const pwshPath = quotePwsh(executable);
    return {
      invokePosix: posixPath,
      invokeFish: posixPath,
      invokePwsh: `& ${pwshPath}`,
      availablePosix: `[ -x ${posixPath} ]`,
      availableFish: `test -x ${posixPath}`,
      availablePwsh: `Test-Path -LiteralPath ${pwshPath}`,
    };
  }

  if (scriptPath) {
    const posixScript = quotePosix(scriptPath);
    const pwshScript = quotePwsh(scriptPath);
    return {
      invokePosix: `bun run ${posixScript}`,
      invokeFish: `bun run ${posixScript}`,
      invokePwsh: `bun run ${pwshScript}`,
      availablePosix: "command -v bun >/dev/null 2>&1",
      availableFish: "type -q bun",
      availablePwsh: "Get-Command bun -ErrorAction SilentlyContinue",
    };
  }

  const fallback = "shellshield";
  return {
    invokePosix: fallback,
    invokeFish: fallback,
    invokePwsh: fallback,
    availablePosix: "command -v shellshield >/dev/null 2>&1",
    availableFish: "type -q shellshield",
    availablePwsh: "Get-Command shellshield -ErrorAction SilentlyContinue",
  };
}

function userConfigPath(): string {
  return join(homedir(), ".shellshield.json");
}

function readUserConfig(path: string): Record<string, unknown> {
  if (!existsSync(path)) return {};
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    return {};
  }
  return {};
}

function writeUserConfig(path: string, content: Record<string, unknown>): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(content, null, 2) + "\n", "utf8");
}

function persistMode(mode: ShellShieldMode): string {
  const path = userConfigPath();
  const cfg = readUserConfig(path);
  cfg.mode = mode;
  writeUserConfig(path, cfg);
  return path;
}

function parseModeSelectionInput(input: string, current: ShellShieldMode): ShellShieldMode | null {
  const normalized = input.trim().toLowerCase();
  if (!normalized) return current;
  if (normalized === "1") return "enforce";
  if (normalized === "2") return "interactive";
  if (normalized === "3") return "permissive";
  if (isValidMode(normalized)) return normalized;
  return null;
}

async function promptModeSelection(current: ShellShieldMode): Promise<ShellShieldMode> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  try {
    const menu =
      "\nShellShield Mode Selector\n" +
      "1) enforce (recommended)\n" +
      "2) interactive\n" +
      "3) permissive\n" +
      `Current: ${current}\n`;

    while (true) {
      const answer = await new Promise<string>((resolve) => {
        rl.question(`${menu}Choose [1-3] (Enter keeps current): `, resolve);
      });

      const selected = parseModeSelectionInput(answer, current);
      if (selected) return selected;
      console.error("Invalid option. Use 1, 2, 3, or mode name.");
    }
  } finally {
    rl.close();
  }
}

function printModeHelp(): void {
  console.log("Usage:");
  console.log("  shellshield --mode");
  console.log("  shellshield --mode <enforce|interactive|permissive>");
  console.log("  shellshield --select-mode");
}

function auditLogPath(): string {
  const override = (process.env.SHELLSHIELD_AUDIT_PATH || "").trim();
  if (override.length > 0) return override;

  const dirOverride = (process.env.SHELLSHIELD_AUDIT_DIR || "").trim();
  const baseDir = dirOverride.length > 0 ? dirOverride : join(homedir(), ".shellshield");
  return join(baseDir, "audit.log");
}

function parseAuditEntry(line: string): AuditLogEntry | null {
  try {
    const parsed = JSON.parse(line);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as AuditLogEntry;
    }
  } catch {
    return null;
  }
  return null;
}

function hasTriggeredRule(entry: AuditLogEntry): boolean {
  if (entry.blocked === true) return true;
  if (typeof entry.reason === "string" && entry.reason.trim().length > 0) return true;
  if (typeof entry.rule === "string" && entry.rule.trim().length > 0) return true;
  if (entry.decision === "blocked" || entry.decision === "warn" || entry.decision === "approved") return true;
  return false;
}

function readLastTriggeredAuditEntry(path: string): AuditLogEntry | null {
  if (!existsSync(path)) return null;
  try {
    const content = readFileSync(path, "utf8");
    const lines = content.split(/\r?\n/).filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      const entry = parseAuditEntry(lines[i]);
      if (!entry) continue;
      if (hasTriggeredRule(entry)) return entry;
    }
  } catch {
    return null;
  }
  return null;
}

function handleWhy(): void {
  const path = auditLogPath();
  if (!existsSync(path)) {
    console.log(`No audit log found at: ${path}`);
    process.exit(0);
  }

  const entry = readLastTriggeredAuditEntry(path);
  if (!entry) {
    console.log("No triggered rules found in audit log yet.");
    console.log(`Log: ${path}`);
    process.exit(0);
  }

  const decision = entry.decision || (entry.blocked ? "blocked" : "allowed");
  const reason = entry.reason || "N/A";
  const suggestion = entry.suggestion || "N/A";
  const command = entry.command || "N/A";

  console.log("ShellShield Why");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  if (entry.timestamp) console.log(`Timestamp: ${entry.timestamp}`);
  console.log(`Decision: ${decision}`);
  if (entry.mode) console.log(`Mode: ${entry.mode}`);
  if (entry.source) console.log(`Source: ${entry.source}`);
  if (entry.rule) console.log(`Rule: ${entry.rule}`);
  console.log(`Reason: ${reason}`);
  console.log(`Suggestion: ${suggestion}`);
  console.log(`Command: ${command}`);
  console.log(`Log: ${path}`);
  process.exit(0);
}

function readAuditEntries(path: string): AuditLogEntry[] {
  if (!existsSync(path)) return [];
  try {
    const content = readFileSync(path, "utf8");
    const lines = content.split(/\r?\n/).filter(Boolean);
    const entries: AuditLogEntry[] = [];
    for (const line of lines) {
      const parsed = parseAuditEntry(line);
      if (parsed) entries.push(parsed);
    }
    return entries;
  } catch {
    return [];
  }
}

function extractRunUrl(command: string | undefined): string | undefined {
  if (!command) return undefined;
  const prefix = "shellshield run ";
  if (!command.startsWith(prefix)) return undefined;
  const value = command.slice(prefix.length).trim();
  return value.length > 0 ? value : undefined;
}

function isRunReceiptEntry(entry: AuditLogEntry): boolean {
  if (entry.source === "run") return true;
  return typeof extractRunUrl(entry.command) === "string";
}

function handleReceipt(args: string[]): void {
  const path = auditLogPath();
  if (!existsSync(path)) {
    console.log(`No audit log found at: ${path}`);
    process.exit(0);
  }

  const entries = readAuditEntries(path).filter(isRunReceiptEntry);
  if (entries.length === 0) {
    console.log("No run receipts found yet.");
    console.log("Run a script first: shellshield --run <url>");
    console.log(`Log: ${path}`);
    process.exit(0);
  }

  const json = args.includes("--json");
  const list = args.includes("--list");
  const countIdx = args.indexOf("--count");
  const rawCount = countIdx !== -1 ? Number.parseInt(args[countIdx + 1] || "", 10) : 10;
  const count = Number.isFinite(rawCount) && rawCount > 0 ? Math.min(rawCount, 100) : 10;

  if (list) {
    const selected = entries.slice(-count).reverse();
    if (json) {
      console.log(JSON.stringify(selected, null, 2));
      process.exit(0);
    }

    console.log("ShellShield Receipts");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    for (const entry of selected) {
      const decision = entry.decision || (entry.blocked ? "blocked" : "allowed");
      const url = extractRunUrl(entry.command) || "(unknown url)";
      const timestamp = entry.timestamp || "(no timestamp)";
      console.log(`- ${timestamp}  ${decision}  ${url}`);
    }
    console.log(`Log: ${path}`);
    process.exit(0);
  }

  const entry = entries[entries.length - 1];
  if (json) {
    console.log(JSON.stringify(entry, null, 2));
    process.exit(0);
  }

  const decision = entry.decision || (entry.blocked ? "blocked" : "allowed");
  const url = extractRunUrl(entry.command) || "(unknown url)";

  console.log("ShellShield Receipt");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  if (entry.id) console.log(`ID: ${entry.id}`);
  if (entry.timestamp) console.log(`Timestamp: ${entry.timestamp}`);
  console.log(`URL: ${url}`);
  console.log(`Decision: ${decision}`);
  if (entry.mode) console.log(`Mode: ${entry.mode}`);
  if (entry.source) console.log(`Source: ${entry.source}`);
  if (entry.rule) console.log(`Rule: ${entry.rule}`);
  if (entry.reason) console.log(`Reason: ${entry.reason}`);
  if (entry.suggestion) console.log(`Details: ${entry.suggestion}`);
  console.log(`Log: ${path}`);
  process.exit(0);
}

function shouldAnalyzeScriptLine(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return false;
  if (/^(if|then|fi|for|while|until|do|done|case|esac|function)\b/i.test(trimmed)) return false;
  if (trimmed === "{" || trimmed === "}") return false;

  return /\b(rm|shred|dd|mkfs|find|xargs|curl|wget|bash|sh|zsh|python|node|ruby|perl|php|systemctl)\b|[|`]|(\$\()|(&&)|(\|\|)|(;)/i.test(
    trimmed
  );
}

function analyzeRemoteScript(script: string, config: Config): ScriptFinding[] {
  const findings: ScriptFinding[] = [];
  const lines = script.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!shouldAnalyzeScriptLine(line)) continue;

    const result = checkDestructive(line, 0, config);
    if (!result.blocked) continue;

    findings.push({
      line: i + 1,
      command: line,
      reason: result.reason,
      suggestion: result.suggestion,
      rule: result.rule,
    });

    if (findings.length >= 20) break;
  }

  return findings;
}

function printScriptPreview(script: string, limit = 30): void {
  const lines = script.split(/\r?\n/);
  const capped = lines.slice(0, limit);
  const width = String(Math.max(capped.length, 1)).length;
  for (let i = 0; i < capped.length; i++) {
    const n = String(i + 1).padStart(width, " ");
    const value = capped[i].length > 200 ? `${capped[i].slice(0, 200)}...` : capped[i];
    console.log(`${n} | ${value}`);
  }
  if (lines.length > capped.length) {
    console.log(`... (${lines.length - capped.length} more lines)`);
  }
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

async function promptYesNo(message: string): Promise<boolean> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) return false;

  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  try {
    const answer = await new Promise<string>((resolve) => {
      rl.question(message, resolve);
    });
    const lower = answer.trim().toLowerCase();
    return lower === "y" || lower === "yes";
  } finally {
    rl.close();
  }
}

async function checkAndAuditCommand(
  command: string,
  config: Config,
  source: "check" | "paste" | "stdin"
): Promise<boolean> {
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

async function handleCheck(args: string[], config: Config): Promise<void> {
  const cmdIdx = args.indexOf("--check");
  const command = args[cmdIdx + 1];
  if (!command) process.exit(0);

  if (hasBypassPrefix(command)) {
    process.exit(0);
  }

  const ok = await checkAndAuditCommand(command, config, "check");
  process.exit(ok ? 0 : 2);
}

async function handlePaste(config: Config): Promise<void> {
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

function handleSnapshot(args: string[], config: Config): void {
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

function handleScore(args: string[], config: Config): void {
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

async function handleRun(args: string[], config: Config): Promise<void> {
  const idx = args.indexOf("--run");
  const url = args[idx + 1];
  if (!url || url.startsWith("--")) {
    console.error("Usage: shellshield --run <url> [--yes] [--force] [--dry-run]");
    process.exit(1);
  }

  const autoApprove = args.includes("--yes");
  const force = args.includes("--force");
  const dryRun = args.includes("--dry-run");
  const runCommand = `shellshield run ${url}`;
  const risk = scoreUrlRisk(url, config.trustedDomains);

  if (risk.reasons.includes("INVALID_URL")) {
    console.error(`Invalid URL: ${url}`);
    process.exit(1);
  }

  let script = "";
  let contentType = "";
  try {
    const response = await fetch(url);
    if (!response.ok) {
      console.error(`Failed to download script: HTTP ${response.status}`);
      process.exit(1);
    }
    contentType = response.headers.get("content-type") || "";
    script = await response.text();
  } catch (error) {
    console.error(`Failed to download script: ${String(error)}`);
    process.exit(1);
  }

  if (!script.trim()) {
    const reason = "REMOTE SCRIPT EMPTY";
    logAudit(
      runCommand,
      {
        blocked: true,
        reason,
        suggestion: "The downloaded script is empty. Review the URL before retrying.",
        rule: "RemoteRun",
      },
      { source: "run", mode: config.mode, threshold: config.threshold, decision: "blocked" }
    );
    console.error(reason);
    process.exit(2);
  }

  const bytes = new TextEncoder().encode(script).length;
  if (bytes > 1024 * 1024) {
    const reason = "REMOTE SCRIPT TOO LARGE";
    logAudit(
      runCommand,
      {
        blocked: true,
        reason,
        suggestion: "Script is larger than 1MB. Download manually and inspect before executing.",
        rule: "RemoteRun",
      },
      { source: "run", mode: config.mode, threshold: config.threshold, decision: "blocked" }
    );
    console.error(reason);
    process.exit(2);
  }

  const scriptHash = createHash("sha256").update(script).digest("hex");
  const lineCount = script.split(/\r?\n/).length;
  const findings = analyzeRemoteScript(script, config);

  console.log("ShellShield Remote Run");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`URL: ${url}`);
  console.log(`Content-Type: ${contentType || "(unknown)"}`);
  console.log(`Bytes: ${bytes}`);
  console.log(`Lines: ${lineCount}`);
  console.log(`SHA256: ${scriptHash}`);
  console.log(`Risk Score: ${risk.score}/100`);
  if (risk.reasons.length > 0) {
    console.log(`Risk Reasons: ${risk.reasons.join(", ")}`);
  }
  console.log(`Trusted Domain: ${risk.trusted ? "yes" : "no"}`);
  console.log(`Findings: ${findings.length}`);
  if (findings.length > 0) {
    for (const finding of findings.slice(0, 5)) {
      console.log(`- L${finding.line}: ${finding.reason} (${finding.command})`);
    }
    if (findings.length > 5) {
      console.log(`- ... and ${findings.length - 5} more findings`);
    }
  }
  console.log("");
  console.log("Preview:");
  printScriptPreview(script, 30);
  console.log("");

  const highRisk = risk.score >= 70;
  if (!force && config.mode === "enforce" && (highRisk || findings.length > 0)) {
    const reason = highRisk ? "REMOTE URL RISK TOO HIGH" : "REMOTE SCRIPT FINDINGS DETECTED";
    const suggestion = highRisk
      ? "Use a trusted HTTPS source, or run again with --force after manual review."
      : "Script contains commands blocked in enforce mode. Review before executing.";
    logAudit(
      runCommand,
      { blocked: true, reason, suggestion, rule: "RemoteRun" },
      { source: "run", mode: config.mode, threshold: config.threshold, decision: "blocked" }
    );
    console.error(reason);
    console.error(`Suggestion: ${suggestion}`);
    process.exit(2);
  }

  if (dryRun) {
    const details = `dry-run; sha256=${scriptHash}; risk=${risk.score}; findings=${findings.length}`;
    logAudit(
      runCommand,
      { blocked: false, reason: "REMOTE SCRIPT REVIEWED", suggestion: details, rule: "RemoteRun" },
      { source: "run", mode: config.mode, threshold: config.threshold, decision: "allowed" }
    );
    console.log("Dry run complete. Script was not executed.");
    process.exit(0);
  }

  if (!autoApprove && (!process.stdin.isTTY || !process.stderr.isTTY)) {
    logAudit(
      runCommand,
      {
        blocked: true,
        reason: "REMOTE SCRIPT CONFIRMATION REQUIRED",
        suggestion: "Re-run with --yes to execute non-interactively.",
        rule: "RemoteRun",
      },
      { source: "run", mode: config.mode, threshold: config.threshold, decision: "blocked" }
    );
    console.error("Interactive confirmation required. Re-run with --yes to execute non-interactively.");
    process.exit(1);
  }

  if (!autoApprove) {
    const confirmed = await promptYesNo("Execute downloaded script now? [y/N] ");
    if (!confirmed) {
      logAudit(
        runCommand,
        {
          blocked: true,
          reason: "REMOTE SCRIPT EXECUTION CANCELLED",
          suggestion: "Execution cancelled by user.",
          rule: "RemoteRun",
        },
        { source: "run", mode: config.mode, threshold: config.threshold, decision: "blocked" }
      );
      process.exit(2);
    }
  }

  const runDir = join(homedir(), ".shellshield", "tmp");
  mkdirSync(runDir, { recursive: true });
  const tempPath = join(runDir, `run-${Date.now()}-${Math.random().toString(16).slice(2)}.sh`);
  writeFileSync(tempPath, script, "utf8");

  let exitCode = 1;
  try {
    const proc = Bun.spawnSync({
      cmd: ["bash", tempPath],
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
    });
    exitCode = proc.exitCode ?? 1;
  } finally {
    try {
      unlinkSync(tempPath);
    } catch {
      // ignore cleanup failures
    }
  }

  const details = `sha256=${scriptHash}; risk=${risk.score}; findings=${findings.length}`;
  if (exitCode === 0) {
    logAudit(
      runCommand,
      { blocked: false, reason: "REMOTE SCRIPT EXECUTED", suggestion: details, rule: "RemoteRun" },
      { source: "run", mode: config.mode, threshold: config.threshold, decision: "approved" }
    );
    process.exit(0);
  }

  logAudit(
    runCommand,
    { blocked: false, reason: `REMOTE SCRIPT EXIT CODE ${exitCode}`, suggestion: details, rule: "RemoteRun" },
    { source: "run", mode: config.mode, threshold: config.threshold, decision: "warn" }
  );
  process.exit(exitCode);
}

function handleMode(args: string[], config: Config): void {
  const idx = args.indexOf("--mode");
  const value = idx !== -1 ? args[idx + 1] : "";

  if (value && !value.startsWith("--")) {
    const mode = value.trim().toLowerCase();
    if (!isValidMode(mode)) {
      console.error(`Invalid mode: ${value}`);
      printModeHelp();
      process.exit(1);
    }
    const path = persistMode(mode);
    console.log(`Mode updated: ${mode}`);
    console.log(`Saved to: ${path}`);
    process.exit(0);
  }

  console.log(`Current mode: ${config.mode}`);
  if (process.env.SHELLSHIELD_MODE) {
    console.log("Source: SHELLSHIELD_MODE (env override)");
  } else {
    console.log(`Source: ${userConfigPath()} or default`);
  }
  printModeHelp();
  process.exit(0);
}

async function handleSelectMode(config: Config): Promise<void> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    console.error("Mode selector requires an interactive TTY.");
    printModeHelp();
    process.exit(1);
  }

  const selected = await promptModeSelection(config.mode);
  const path = persistMode(selected);
  console.log(`Mode updated: ${selected}`);
  console.log(`Saved to: ${path}`);
  process.exit(0);
}

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
  const initCmd = resolveInitCommandContext();
  const rendered = template
    .replaceAll("{{CLI_INVOKE_POSIX}}", initCmd.invokePosix)
    .replaceAll("{{CLI_INVOKE_FISH}}", initCmd.invokeFish)
    .replaceAll("{{CLI_INVOKE_PWSH}}", initCmd.invokePwsh)
    .replaceAll("{{CLI_AVAILABLE_POSIX}}", initCmd.availablePosix)
    .replaceAll("{{CLI_AVAILABLE_FISH}}", initCmd.availableFish)
    .replaceAll("{{CLI_AVAILABLE_PWSH}}", initCmd.availablePwsh);
  console.log(rendered);
  process.exit(0);
}

async function handleStdin(config: Config): Promise<void> {
  try {
    const input = await Bun.stdin.text();
    if (!input || input.trim() === "") process.exit(0);

    let command = "";
    try {
      const data: ToolInput = JSON.parse(input);
      command = data.tool_input?.command ?? data.command ?? "";
    } catch {
      command = input.trim();
    }

    if (!command || command.trim() === "" || hasBypassPrefix(command)) {
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

  if (isBypassEnabled(process.env.SHELLSHIELD_SKIP)) {
    process.exit(0);
  }

  if (args.includes("--init")) {
    handleInit();
  }

  if (args.includes("--stats")) {
    printStats();
    process.exit(0);
  }

  if (args.includes("--why")) {
    handleWhy();
  }

  if (args.includes("--receipt")) {
    handleReceipt(args);
  }

  if (args.includes("--mode")) {
    handleMode(args, config);
  }

  if (args.includes("--select-mode")) {
    await handleSelectMode(config);
  }

  if (args.includes("--doctor")) {
    printDoctor();
    process.exit(0);
  }

  if (args.includes("--score")) {
    handleScore(args, config);
  }

  if (args.includes("--run")) {
    await handleRun(args, config);
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
