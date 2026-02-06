import { ParsedEntry } from "./types";

export function normalizeCommandName(token: string): string {
  if (!token) return "";
  const stripped = token.startsWith("\\") ? token.slice(1) : token;
  const basenamePart = stripped.split("/").pop() ?? "";
  return basenamePart.toLowerCase();
}

export function resolveVariable(token: string, vars: Record<string, string>): string | null {
  if (!token) return null;
  
  let name = "";
  let fallback = "";

  if (token.startsWith("${") && token.endsWith("}")) {
    const inner = token.slice(2, -1);
    const defaultIdx = inner.indexOf(":-");
    name = defaultIdx >= 0 ? inner.slice(0, defaultIdx) : inner;
    fallback = defaultIdx >= 0 ? inner.slice(defaultIdx + 2) : "";
  } else if (token.startsWith("$")) {
    const inner = token.slice(1);
    const defaultIdx = inner.indexOf(":-");
    name = defaultIdx >= 0 ? inner.slice(0, defaultIdx) : inner;
    fallback = defaultIdx >= 0 ? inner.slice(defaultIdx + 2) : "";
  } else {
    return null;
  }

  const val = vars[name] ?? process.env[name];
  if (val && val.length > 0) return val;
  return fallback.length > 0 ? fallback : null;
}

export function filterFlags(args: string[]): string[] {
  return args.filter((arg) => !arg.startsWith("-"));
}

export function getTrashSuggestion(files: string[]): string {
  if (files.length === 0) return "trash <files>";
  return `trash ${files.join(" ")}`;
}
