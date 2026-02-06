import { homedir } from "node:os";
import { CRITICAL_PATHS, SENSITIVE_PATTERNS } from "../constants";

export function isCriticalPath(path: string): boolean {
  let normalized = path.toLowerCase().replace(/\\/g, "/");

  if (/^[a-z]:[^\/]/.test(normalized)) {
    normalized = normalized[0] + ":" + "/" + normalized.slice(2);
  }

  normalized = normalized.replace(/\/+$/, "");
  if (!normalized || normalized === "/" || /^[a-z]:$/.test(normalized)) return true;

  if (CRITICAL_PATHS.has(normalized) || CRITICAL_PATHS.has(normalized.replace(/\//g, ""))) {
    return true;
  }

  for (const critical of CRITICAL_PATHS) {
    if (critical === "/" || critical === "c:") continue;
    if (normalized.startsWith(critical + "/") || normalized.startsWith(critical + "\\")) {
      return true;
    }
  }

  if (normalized === ".git" || normalized.endsWith("/.git") || normalized.endsWith(".git")) {
    return true;
  }
  return false;
}

export function isSensitivePath(path: string): boolean {
  const normalized = path.replace(/\/+$/, "");
  let fullPath = normalized;
  if (normalized.startsWith("~")) {
    const home = homedir();
    fullPath = normalized.replace("~", home);
  }
  for (const pattern of SENSITIVE_PATTERNS) {
    if (pattern.test(fullPath)) return true;
  }
  return false;
}
