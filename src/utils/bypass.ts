const BYPASS_VALUES = new Set(["1", "true", "yes", "on", "enable", "enabled"]);

export function isBypassEnabled(value: string | undefined): boolean {
  if (!value) return false;
  return BYPASS_VALUES.has(value.toLowerCase().trim());
}

export function extractEnvVar(
  tokens: Array<string | { op: string }>,
  varName: string
): string | undefined {
  for (const token of tokens) {
    if (typeof token !== "string") break;

    if (token.includes("=")) {
      const [key, ...valueParts] = token.split("=");
      if (key === varName) {
        return valueParts.join("=");
      }
      continue;
    }

    break;
  }
  return undefined;
}