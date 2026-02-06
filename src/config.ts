import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { z } from "zod";
import { Config } from "./types";
import { DEFAULT_BLOCKED, DEFAULT_TRUSTED_DOMAINS } from "./constants";

const ConfigSchema = z.object({
  blocked: z.array(z.string()).optional(),
  allowed: z.array(z.string()).optional(),
  trustedDomains: z.array(z.string()).optional(),
  threshold: z.number().int().positive().optional(),
  maxSubshellDepth: z.number().int().min(0).optional(),
  contextPath: z.string().min(1).optional(),
  mode: z.enum(["enforce", "permissive", "interactive"]).optional(),
  customRules: z
    .array(
      z.object({
        pattern: z.string(),
        suggestion: z.string(),
      })
    )
    .optional(),
});

type FileConfig = z.infer<typeof ConfigSchema>;

function readConfigFile(path: string): FileConfig | null {
  if (!existsSync(path)) return null;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    const parsed = ConfigSchema.safeParse(raw);
    if (!parsed.success) {
      if (process.env.DEBUG) {
        const issues = parsed.error.issues
          .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
          .join("; ");
        console.warn(`[ShellShield] Invalid config at ${path}: ${issues}`);
      }
      return null;
    }
    return parsed.data;
  } catch {
    return null;
  }
}

function loadConfigFile(): Partial<Config> {
  const scriptPath = process.argv[1] || "";
  const candidateDirs = [
    process.env.INIT_CWD || "",
    process.env.PWD || "",
    process.cwd(),
    scriptPath ? dirname(scriptPath) : "",
    scriptPath ? dirname(dirname(scriptPath)) : "",
  ].filter(Boolean);

  let localPath = "";
  for (const dir of candidateDirs) {
    const candidate = join(dir, ".shellshield.json");
    if (existsSync(candidate)) {
      localPath = candidate;
      break;
    }
  }

  const homePath = join(homedir(), ".shellshield.json");

  const homeConfig = readConfigFile(homePath);
  const localConfig = localPath ? readConfigFile(localPath) : null;

  const blockedSource = localConfig?.blocked ?? homeConfig?.blocked;
  const allowedSource = localConfig?.allowed ?? homeConfig?.allowed;
  const trustedDomains = localConfig?.trustedDomains ?? homeConfig?.trustedDomains;
  const threshold = localConfig?.threshold ?? homeConfig?.threshold;
  const maxSubshellDepth = localConfig?.maxSubshellDepth ?? homeConfig?.maxSubshellDepth;
  const contextPath = localConfig?.contextPath ?? homeConfig?.contextPath;
  const mode = localConfig?.mode ?? homeConfig?.mode;
  const customRules = localConfig?.customRules ?? homeConfig?.customRules;

  return {
    blocked: blockedSource
      ? new Set(blockedSource.map((command) => command.toLowerCase()))
      : undefined,
    allowed: allowedSource
      ? new Set(allowedSource.map((command) => command.toLowerCase()))
      : undefined,
    trustedDomains,
    threshold,
    maxSubshellDepth,
    contextPath,
    mode,
    customRules,
  };
}

export function getConfiguration(): Config {
  const fileConfig = loadConfigFile();

  const blocked = fileConfig.blocked || new Set(DEFAULT_BLOCKED);
  const allowed = fileConfig.allowed || new Set<string>();
  const trustedDomains = fileConfig.trustedDomains || DEFAULT_TRUSTED_DOMAINS;

  const threshold =
    fileConfig.threshold || Number.parseInt(process.env.SHELLSHIELD_THRESHOLD || "50", 10);

  const maxSubshellDepth =
    fileConfig.maxSubshellDepth ??
    (Number.parseInt(process.env.SHELLSHIELD_MAX_SUBSHELL_DEPTH || "5", 10) || 5);

  const mode =
    (process.env.SHELLSHIELD_MODE as "enforce" | "permissive" | "interactive") ||
    fileConfig.mode ||
    "enforce";

  const customRules = fileConfig.customRules || [];

  if (!process.env.SHELLSHIELD_CONTEXT_PATH && fileConfig.contextPath) {
    process.env.SHELLSHIELD_CONTEXT_PATH = fileConfig.contextPath;
  }

  if (process.env.OPENCODE_BLOCK_COMMANDS) {
    process.env.OPENCODE_BLOCK_COMMANDS.split(",").forEach((cmd) =>
      blocked.add(cmd.trim().toLowerCase())
    );
  }

  if (process.env.OPENCODE_ALLOW_COMMANDS) {
    process.env.OPENCODE_ALLOW_COMMANDS.split(",").forEach((cmd) =>
      allowed.add(cmd.trim().toLowerCase())
    );
  }

  return {
    blocked,
    allowed,
    trustedDomains,
    threshold,
    maxSubshellDepth,
    contextPath: fileConfig.contextPath,
    mode,
    customRules,
  };
}
