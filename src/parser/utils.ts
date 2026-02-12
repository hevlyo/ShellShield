export function normalizeCommandName(token: string): string {
  if (!token) return "";
  const stripped = token.startsWith("\\") ? token.slice(1) : token;
  const normalized = stripped.replaceAll("\\", "/");
  const basenamePart = normalized.split("/").pop() ?? "";
  return basenamePart.toLowerCase();
}

export function resolveVariable(token: string, vars: Record<string, string>): string {
  if (!token) return "";

  return token.replace(/\$\{([^}:-]+)(?::-([^}]+))?\}|\$([a-zA-Z_][a-zA-Z0-9_]*)/g, (match, braceName, fallback, simpleName) => {
    const name = braceName || simpleName;
    const val = vars[name] ?? process.env[name];

    // If using :- operator, treat empty string as unset and use fallback
    if (fallback !== undefined) {
      if (val && val.length > 0) {
        return val;
      }
      return fallback;
    }

    // Without :- operator, return value if defined (even if empty)
    if (val !== undefined && val !== null) {
      return val;
    }

    return match;
  });
}

export function filterFlags(args: string[]): string[] {
  return args.filter((arg) => !arg.startsWith("-"));
}

export function getTrashSuggestion(files: string[]): string {
  if (files.length === 0) return "trash <files>";
  return `trash ${files.join(" ")}`;
}
