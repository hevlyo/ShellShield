import { appendFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { BlockResult } from "./types";

export function logAudit(command: string, result: BlockResult): void {
  try {
    const auditDir = join(homedir(), ".shellshield");
    if (!existsSync(auditDir)) mkdirSync(auditDir, { recursive: true });
    const logPath = join(auditDir, "audit.log");
    const entry = {
      timestamp: new Date().toISOString(),
      command,
      blocked: result.blocked,
      reason: result.blocked ? result.reason : undefined,
      cwd: process.cwd(),
    };
    appendFileSync(logPath, JSON.stringify(entry) + "\n");
  } catch {
    return;
  }
}
