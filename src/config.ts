import { existsSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";
import { Config } from "./types";
import { DEFAULT_BLOCKED, DEFAULT_TRUSTED_DOMAINS } from "./constants";

interface FileConfig {
  blocked?: string[];
  allowed?: string[];
  trustedDomains?: string[];
  threshold?: number;
}

function readConfigFile(path: string): FileConfig | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as FileConfig;
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

  return {
    blocked: blockedSource
      ? new Set(blockedSource.map((command) => command.toLowerCase()))
      : undefined,
    allowed: allowedSource
      ? new Set(allowedSource.map((command) => command.toLowerCase()))
      : undefined,
    trustedDomains,
    threshold,
  };
}

export function getConfiguration(): Config {
  const fileConfig = loadConfigFile();
  const blocked = fileConfig.blocked || new Set(DEFAULT_BLOCKED);
  const allowed = fileConfig.allowed || new Set<string>();
  const trustedDomains = fileConfig.trustedDomains || DEFAULT_TRUSTED_DOMAINS;
  const threshold =
    fileConfig.threshold || parseInt(process.env.SHELLSHIELD_THRESHOLD || "50", 10);

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

  return { blocked, allowed, trustedDomains, threshold };
}
