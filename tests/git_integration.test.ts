import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hasUncommittedChanges } from "../src/integrations/git";

function runGit(cwd: string, args: string[]) {
  const proc = Bun.spawnSync({
    cmd: ["git", ...args],
    cwd,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "shellshield",
      GIT_AUTHOR_EMAIL: "shellshield@example.com",
      GIT_COMMITTER_NAME: "shellshield",
      GIT_COMMITTER_EMAIL: "shellshield@example.com",
    },
  });
  if (proc.exitCode !== 0) {
    throw new Error(proc.stderr.toString() || `git ${args.join(" ")} failed`);
  }
}

describe("Git integration", () => {
  test("batches git status calls for multiple files", () => {
    const repoDir = mkdtempSync(join(tmpdir(), "shellshield-git-"));
    runGit(repoDir, ["init"]);

    const fileA = join(repoDir, "a.txt");
    const fileB = join(repoDir, "b.txt");
    writeFileSync(fileA, "a1\n");
    writeFileSync(fileB, "b1\n");

    runGit(repoDir, ["add", "."]);
    runGit(repoDir, ["commit", "-m", "init"]);

    writeFileSync(fileA, "a2\n");

    const changed = hasUncommittedChanges([fileA, fileB]);
    expect(changed).toContain(fileA);
    expect(changed).not.toContain(fileB);
  });

  test("handles ./pathspec mapping for relative files", () => {
    const repoDir = mkdtempSync(join(tmpdir(), "shellshield-git-"));
    runGit(repoDir, ["init"]);

    const fileA = join(repoDir, "a.txt");
    writeFileSync(fileA, "a1\n");
    runGit(repoDir, ["add", "."]);
    runGit(repoDir, ["commit", "-m", "init"]);

    writeFileSync(fileA, "a2\n");

    const originalCwd = process.cwd();
    try {
      process.chdir(repoDir);
      const changed = hasUncommittedChanges(["./a.txt"]);
      expect(changed).toContain("./a.txt");
    } finally {
      process.chdir(originalCwd);
    }
  });

  test("returns empty list when files input is invalid", () => {
    const changed = hasUncommittedChanges(null as unknown as string[]);
    expect(changed).toEqual([]);
  });
});
