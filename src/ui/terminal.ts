export interface AnsiPalette {
  red: string;
  yellow: string;
  cyan: string;
  dim: string;
  gray: string;
  bold: string;
  reset: string;
}

export function getAnsiPalette(isTty: boolean): AnsiPalette {
  return {
    red: isTty ? "\x1b[31m" : "",
    yellow: isTty ? "\x1b[33m" : "",
    cyan: isTty ? "\x1b[36m" : "",
    dim: isTty ? "\x1b[2m" : "",
    gray: isTty ? "\x1b[90m" : "",
    bold: isTty ? "\x1b[1m" : "",
    reset: isTty ? "\x1b[0m" : "",
  };
}

export function formatBlockedMessage(reason: string, suggestion: string, isTty: boolean): string {
  const { red, yellow, cyan, dim, gray, bold, reset } = getAnsiPalette(isTty);
  const line = `${gray}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${reset}`;

  const highlightedSuggestion = suggestion.replaceAll(
    /(\/[^\s"']+|[A-Za-z]:\\[^\s"']+)/g,
    `${cyan}$1${reset}`
  );

  return (
    `\n${red}🛡️ ${reset}ShellShield ${red}BLOCKED${reset}: ${reason}\n` +
    `${line}\n` +
    `${bold}${yellow}ACTION REQUIRED:${reset} ${highlightedSuggestion}\n` +
    `${line}\n` +
    `${dim}Bypass: SHELLSHIELD_SKIP=1 <command>${reset}\n` +
    `${dim}Hint:   set SHELLSHIELD_MODE=interactive for quick prompts${reset}\n` +
    `${dim}ShellShield - Keeping your terminal safe.${reset}`
  );
}
