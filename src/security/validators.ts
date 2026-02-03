import { TerminalInjectionResult } from "../types";

export function hasHomograph(str: string): { detected: boolean; char?: string } {
  for (const char of str) {
    const code = char.charCodeAt(0);
    const isHidden = /[\u200B-\u200D\uFEFF]/.test(char);
    if (code > 127 && !isHidden) {
      return { detected: true, char };
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
