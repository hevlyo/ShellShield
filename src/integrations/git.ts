import { execFileSync } from "node:child_process";
import { basename, dirname } from "node:path";

function processGitStatusOutput(
  out: string,
  entries: Array<{ original: string; pathspec: string }>,
  results: Set<string>
): void {
  const pathspecToOriginal = new Map<string, string>();
  for (const entry of entries) {
    pathspecToOriginal.set(entry.pathspec, entry.original);
    if (entry.pathspec.startsWith("./")) {
      pathspecToOriginal.set(entry.pathspec.slice(2), entry.original);
    }
  }

  for (const line of out.split("\n")) {
    const rawPath = line.slice(3).trim();
    if (!rawPath) continue;
    const pathPart = rawPath.includes("->") ? rawPath.split("->").pop()!.trim() : rawPath;
    const mapped =
      pathspecToOriginal.get(pathPart) ||
      pathspecToOriginal.get(pathPart.replace(/^\.\//, "")) ||
      pathspecToOriginal.get(basename(pathPart));
    if (mapped) results.add(mapped);
  }
}

export function hasUncommittedChanges(files: string[]): string[] {
  try {
    if (files.length === 0) return [];
    const results = new Set<string>();

    const byDir = new Map<string, Array<{ original: string; pathspec: string }>>();
    for (const file of files) {
      if (!file || file.startsWith("-")) continue;
      const isAbsolute = file.startsWith("/");
      const dir = isAbsolute ? dirname(file) : ".";
      const pathspec = isAbsolute ? basename(file) : file;
      const list = byDir.get(dir) ?? [];
      list.push({ original: file, pathspec });
      byDir.set(dir, list);
    }

    for (const [dir, entries] of byDir) {
      try {
        const pathspecs = entries.map((e) => e.pathspec);
        const out = execFileSync(
          "git",
          ["-C", dir, "status", "--porcelain", "--", ...pathspecs],
          {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
          }
        ).trimEnd();

        if (out) {
          processGitStatusOutput(out, entries, results);
        }
      } catch {
        continue;
      }
    }

    return [...results];
  } catch {
    return [];
  }
}
