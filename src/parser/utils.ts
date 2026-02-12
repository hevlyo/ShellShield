import { ParsedEntry } from "./types";

export function normalizeCommandName(token: string): string {
  if (!token) return "";
  const stripped = token.startsWith("\\") ? token.slice(1) : token;
  const basenamePart = stripped.split("/").pop() ?? "";
  return basenamePart.toLowerCase();
}

export function resolveVariable(token: string, vars: Record<string, string>): string {
  if (!token) return "";

  return token.replace(/\$\{([^}:-]+)(?::-([^}]+))?\}|\$([a-zA-Z_][a-zA-Z0-9_]*)/g, (match, braceName, fallback, simpleName) => {
    const name = braceName || simpleName;
    const val = vars[name] ?? process.env[name];

    if (val !== undefined && val !== null) {
      return val;
    }

    return fallback !== undefined ? fallback : match;
  });
}

export function filterFlags(args: string[]): string[] {
  return args.filter((arg) => !arg.startsWith("-"));
}

export function getTrashSuggestion(files: string[]): string {
  if (files.length === 0) return "trash <files>";
  return `trash ${files.join(" ")}`;
}
