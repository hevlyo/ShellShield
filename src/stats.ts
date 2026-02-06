import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

interface AuditEntry {
  timestamp: string;
  command: string;
  blocked: boolean;
  reason?: string;
  severity?: string;
}

export function printStats() {
  const logPath = join(homedir(), ".shellshield", "audit.log");
  if (!existsSync(logPath)) {
    console.log("No audit log found.");
    return;
  }

  const content = readFileSync(logPath, "utf8");
  const lines = content.split("\n").filter(Boolean);
  const entries = lines.map(line => {
    try { return JSON.parse(line) as AuditEntry; } catch { return null; }
  }).filter(Boolean) as AuditEntry[];

  const total = entries.length;
  const blocked = entries.filter(e => e.blocked).length;
  const allowed = total - blocked;
  
  const reasons: Record<string, number> = {};
  entries.forEach(e => {
    if (e.reason) {
      reasons[e.reason] = (reasons[e.reason] || 0) + 1;
    }
  });

  console.log(`
🛡️  ShellShield Statistics
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Commands Analyzed: ${total}
🚫 Blocked: ${blocked}
✅ Allowed: ${allowed}

Top Block Reasons:
${Object.entries(reasons)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 5)
  .map(([r, c]) => `   - ${r}: ${c}`)
  .join("\n")}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`);
}
