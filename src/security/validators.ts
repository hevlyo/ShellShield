import { TerminalInjectionResult } from "../types";

export function hasHomograph(str: string): { detected: boolean; char?: string } {
  const urls = str.match(/https?:\/\/[^\s"'`]+/g) || [];
  const candidates = urls.length > 0 ? urls : str.match(/\b[^\s]+\.[^\s]+\b/g) || [];

  for (const token of candidates) {
    let host = "";
    if (token.includes("://")) {
      host = token.split("://")[1] ?? "";
    } else {
      host = token;
    }

    host = host.split("/")[0] ?? "";
    host = host.split(":")[0] ?? "";

    if (!host.includes(".")) continue;

    const scripts = new Set<string>();
    let suspiciousChar: string | undefined;
    let hasNonAsciiLetter = false;

    for (const char of host) {
      const isHidden = /[\u200B-\u200D\uFEFF]/.test(char);
      if (isHidden) continue;

      const code = char.charCodeAt(0);
      const lower = char.toLowerCase();

      // Only consider letters for script mixing heuristics
      const isAsciiLetter = lower >= "a" && lower <= "z";
      if (isAsciiLetter) {
        scripts.add("latin");
        continue;
      }

      // Cyrillic
      if (code >= 0x0400 && code <= 0x04ff) {
        scripts.add("cyrillic");
        hasNonAsciiLetter = true;
        suspiciousChar = suspiciousChar ?? char;
        continue;
      }

      // Greek
      if (code >= 0x0370 && code <= 0x03ff) {
        scripts.add("greek");
        hasNonAsciiLetter = true;
        suspiciousChar = suspiciousChar ?? char;
        continue;
      }

      // Any other non-ASCII letter-like character
      if (code > 127) {
        // Treat as non-ascii; mark script as other for mixing detection
        scripts.add("other");
        hasNonAsciiLetter = true;
        suspiciousChar = suspiciousChar ?? char;
      }
    }

    // IDN-safe heuristic:
    // - Allow pure non-Latin hostnames (single non-latin script) to reduce false positives.
    // - Block mixed scripts or latin+non-ascii mixes (classic homograph).
    if (hasNonAsciiLetter) {
      if (scripts.has("latin") && scripts.size > 1) {
        return { detected: true, char: suspiciousChar };
      }
      if (scripts.size > 1) {
        return { detected: true, char: suspiciousChar };
      }
    }
  }

  return { detected: false };
}

export function checkTerminalInjection(str: string): TerminalInjectionResult {
  if (/\x1b\[/.test(str)) {
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
