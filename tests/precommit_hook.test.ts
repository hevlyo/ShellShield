import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function run(cmd: string[], cwd: string, env: Record<string, string> = {}) {
  const proc = Bun.spawnSync({
    cmd,
    cwd,
    env: { ...process.env, ...env },
  });
  return {
    code: proc.exitCode,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  };
}

describe("Pre-commit hook", () => {
  test("blocks staged destructive lines", () => {
    const repoDir = mkdtempSync(join(tmpdir(), "shellshield-hook-"));
    const homeDir = mkdtempSync(join(tmpdir(), "shellshield-home-"));
    const shellshieldHome = join(homeDir, ".shellshield", "src");
    mkdirSync(shellshieldHome, { recursive: true });

    // Use the local project ShellShield as the "installed" one.
    const sourceIndex = join(process.cwd(), "src", "index.ts");
    const destIndex = join(shellshieldHome, "index.ts");
    writeFileSync(destIndex, readFileSync(sourceIndex, "utf8"));

    const gitEnv = {
      GIT_AUTHOR_NAME: "shellshield",
      GIT_AUTHOR_EMAIL: "shellshield@example.com",
      GIT_COMMITTER_NAME: "shellshield",
      GIT_COMMITTER_EMAIL: "shellshield@example.com",
    };

    run(["git", "init"], repoDir);
    writeFileSync(join(repoDir, "safe.txt"), "ok\n");
    run(["git", "add", "."], repoDir);
    run(["git", "commit", "-m", "init"], repoDir, gitEnv);

    writeFileSync(join(repoDir, "danger.sh"), "rm -rf /\n");
    run(["git", "add", "danger.sh"], repoDir);

    const installer = join(process.cwd(), "scripts", "install-hook.sh");
    const installRes = run(["bash", installer], repoDir, { HOME: homeDir, PATH: `/home/hevlyo/.bun/bin:${process.env.PATH}` });
    expect(installRes.code).toBe(0);

    const hookPath = join(repoDir, ".git", "hooks", "pre-commit");
    const hookRes = run(["bash", hookPath], repoDir, { HOME: homeDir, PATH: `/home/hevlyo/.bun/bin:${process.env.PATH}` });
    expect(hookRes.code).toBe(1);
    expect(hookRes.stdout + hookRes.stderr).toContain("Commit blocked by ShellShield");

    const bypassRes = run(["bash", hookPath], repoDir, { HOME: homeDir, SHELLSHIELD_SKIP: "1", PATH: `/home/hevlyo/.bun/bin:${process.env.PATH}` });
    expect(bypassRes.code).toBe(0);
  });
});
