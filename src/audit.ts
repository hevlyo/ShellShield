import { appendFileSync, existsSync, mkdirSync, statSync, renameSync } from "node:fs";
import { join } from "node:path";
import { homedir, hostname } from "node:os";
import { createHash } from "node:crypto";
import { BlockResult, Config } from "./types";

export interface AuditMeta {
  mode?: Config["mode"];
  threshold?: number;
  source?: "check" | "stdin" | "paste";
  decision?: "blocked" | "allowed" | "warn" | "approved";
}

function getAuditDir(): string {
  const dir = (process.env.SHELLSHIELD_AUDIT_DIR || "").trim();
  return dir.length > 0 ? dir : join(homedir(), ".shellshield");
}

function getAuditPath(): string {
  const p = (process.env.SHELLSHIELD_AUDIT_PATH || "").trim();
  return p.length > 0 ? p : join(getAuditDir(), "audit.log");
}

function rotateIfNeeded(logPath: string): void {
  if (!existsSync(logPath)) return;
  try {
    if ((process.env.SHELLSHIELD_AUDIT_DISABLED || "").trim() === "1") return;
    const stats = statSync(logPath);
    if (stats.size <= 1 * 1024 * 1024) return;
    const backupPath = logPath + ".1";
    renameSync(logPath, backupPath);
  } catch {
    return;
  }
}

function inferDecision(result: BlockResult, meta: AuditMeta): AuditMeta["decision"] {
  if (meta.decision) return meta.decision;
  if (result.blocked) return "blocked";

  const maybeReason = (result as Partial<{ reason: string }>).reason;
  if (typeof maybeReason === "string" && maybeReason.length > 0) return "warn";
  return "allowed";
}

export function logAudit(command: string, result: BlockResult, meta: AuditMeta = {}): void {
  try {
    const auditDir = getAuditDir();
    if (!existsSync(auditDir)) mkdirSync(auditDir, { recursive: true });

    const logPath = getAuditPath();
    rotateIfNeeded(logPath);

    const commandHash = createHash("sha256").update(command).digest("hex").slice(0, 12);

    const rule = (result as Partial<{ rule: string }>).rule;
    const reason = (result as Partial<{ reason: string }>).reason;
    const suggestion = (result as Partial<{ suggestion: string }>).suggestion;

    const entry = {
      v: 1,
      id: commandHash,
      timestamp: new Date().toISOString(),
      user: process.env.USER || "unknown",
      host: hostname(),
      cwd: process.cwd(),
      shell: process.env.SHELL || undefined,

      command,
      blocked: result.blocked,
      decision: inferDecision(result, meta),
      severity: result.blocked ? "high" : "info",

      rule: typeof rule === "string" && rule.length > 0 ? rule : undefined,
      reason: typeof reason === "string" && reason.length > 0 ? reason : undefined,
      suggestion: typeof suggestion === "string" && suggestion.length > 0 ? suggestion : undefined,

      mode: meta.mode || process.env.SHELLSHIELD_MODE || undefined,
      threshold: typeof meta.threshold === "number" ? meta.threshold : undefined,
      source: meta.source || undefined,

      contextPath: process.env.SHELLSHIELD_CONTEXT_PATH || undefined,
      maxSubshellDepth: process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH || undefined,
    };

    appendFileSync(logPath, JSON.stringify(entry) + "\n");
  } catch {
    return;
  }
}
