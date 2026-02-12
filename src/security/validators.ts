import { TerminalInjectionResult } from "../types";
import { MAX_INPUT_LENGTH } from "./patterns";

function getHostname(token: string): string {
  let host = token.includes("://") ? token.split("://")[1] ?? "" : token;
  host = host.split("/")[0] ?? "";
  return host.split(":")[0] ?? "";
}

function analyzeChar(char: string, scripts: Set<string>): { isNonAscii: boolean } {
  const isHidden = /[\u200B-\u200D\uFEFF]/.test(char);
  if (isHidden) return { isNonAscii: false };

  const code = char.codePointAt(0);
  if (code === undefined) return { isNonAscii: false };
  const lower = char.toLowerCase();

  if (lower >= "a" && lower <= "z") {
    scripts.add("latin");
    return { isNonAscii: false };
  }

  if (code >= 0x0400 && code <= 0x04ff) {
    scripts.add("cyrillic");
    return { isNonAscii: true };
  }

  if (code >= 0x0370 && code <= 0x03ff) {
    scripts.add("greek");
    return { isNonAscii: true };
  }

  if (code > 127) {
    scripts.add("other");
    return { isNonAscii: true };
  }

  return { isNonAscii: false };
}

function isSuspiciousHost(host: string): { detected: boolean; char?: string } {
  if (!host.includes(".")) return { detected: false };

  const scripts = new Set<string>();
  let firstNonAscii: string | undefined;
  let hasNonAsciiLetter = false;

  for (const char of host) {
    const { isNonAscii } = analyzeChar(char, scripts);
    if (isNonAscii) {
      hasNonAsciiLetter = true;
      firstNonAscii = firstNonAscii ?? char;
    }
  }

  if (hasNonAsciiLetter && (scripts.has("latin") && scripts.size > 1 || scripts.size > 1)) {
    return { detected: true, char: firstNonAscii };
  }

  return { detected: false };
}

export function hasHomograph(str: string): { detected: boolean; char?: string; reason?: string } {
  if (str.length > MAX_INPUT_LENGTH) {
    return { detected: true, reason: "INPUT_TOO_LONG", char: "exceeds MAX_INPUT_LENGTH" };
  }

  const urls = str.match(/https?:\/\/[^\s"'`]{0,2000}/g) || [];
  const candidates = urls.length > 0 ? urls : str.match(/\b[^\s]{1,253}\.[^\s]{1,253}\b/g) || [];

  for (const token of candidates) {
    const host = getHostname(token);
    const result = isSuspiciousHost(host);
    if (result.detected) return result;
  }

  return { detected: false };
}

export function checkTerminalInjection(str: string): TerminalInjectionResult {
  if (str.includes("\x1b[")) {
    return { detected: true, reason: "TERMINAL INJECTION DETECTED" };
  }
  if (/[\u200B-\u200D\uFEFF]/.test(str)) {
    return { detected: true, reason: "HIDDEN CHARACTERS DETECTED" };
  }
  return { detected: false };
}

export function isTrustedDomain(url: string, trustedDomains: string[]): boolean {
  try {
    const domain = new URL(url).hostname;
    return trustedDomains.some((trusted) => domain === trusted || domain.endsWith(`.${trusted}`));
  } catch {
    return false;
  }
}

export interface UrlRiskScore {
  url: string;
  score: number;
  reasons: string[];
  trusted: boolean;
}

function isIpHost(hostname: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true;
  if (/^\[[0-9a-f:]+\]$/i.test(hostname)) return true;
  return false;
}

export function scoreUrlRisk(url: string, trustedDomains: string[]): UrlRiskScore {
  const reasons: string[] = [];
  let score = 0;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { url, score: 100, reasons: ["INVALID_URL"], trusted: false };
  }

  const trusted = isTrustedDomain(url, trustedDomains);

  if (parsed.protocol !== "https:") {
    score += 30;
    reasons.push("INSECURE_PROTOCOL");
  }

  if (parsed.username || parsed.password) {
    score += 30;
    reasons.push("CREDENTIALS_IN_URL");
  }

  if (parsed.hostname.includes("xn--")) {
    score += 15;
    reasons.push("PUNYCODE_DOMAIN");
  }

  if (isIpHost(parsed.hostname)) {
    score += 20;
    reasons.push("IP_ADDRESS_HOST");
  }

  const homograph = hasHomograph(url);
  if (homograph.detected) {
    score += 25;
    reasons.push("HOMOGRAPH_MIXED_SCRIPTS");
  }

  if (!trusted) {
    score += 10;
    reasons.push("UNTRUSTED_DOMAIN");
  }

  if (url.length > 100) {
    score += 10;
    reasons.push("LONG_URL");
  }

  score = Math.min(100, score);
  return { url, score, reasons, trusted };
}
