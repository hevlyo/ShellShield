import { execSync } from "child_process";
import { basename, dirname } from "path";

export function hasUncommittedChanges(files: string[]): string[] {
  try {
    if (files.length === 0) return [];
    const results: string[] = [];
    for (const file of files) {
      if (file.startsWith("-")) continue;
      try {
        const isAbsolute = file.startsWith("/");
        const dir = isAbsolute ? dirname(file) : ".";
        const name = isAbsolute ? basename(file) : file;
        const status = execSync(
          `git -C "${dir}" status --porcelain "${name}" 2>/dev/null`,
          { encoding: "utf8" }
        ).trim();
        if (status) results.push(file);
      } catch {
        continue;
      }
    }
    return results;
  } catch {
    return [];
  }
}
