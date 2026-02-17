import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const PROJECT_ROOT = join(import.meta.dir, "..");
const INSTALLER = join(PROJECT_ROOT, "docs", "install.sh");

function installerSha256(): string {
  const content = readFileSync(INSTALLER);
  return createHash("sha256").update(content).digest("hex");
}

describe("Installer script", () => {
  test("install.sh is valid bash", () => {
    const proc = Bun.spawnSync({
      cmd: ["bash", "-n", INSTALLER],
      cwd: PROJECT_ROOT,
    });
    expect(proc.exitCode).toBe(0);
  });

  test("fails fast when bun is missing", () => {
    const proc = Bun.spawnSync({
      cmd: ["bash", INSTALLER],
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        SHELLSHIELD_INSTALL_SHA256: installerSha256(),
        PATH: "/usr/bin:/bin",
        HOME: "/tmp",
      },
    });
    const out = (proc.stdout?.toString() ?? "") + (proc.stderr?.toString() ?? "");
    expect(proc.exitCode).toBe(1);
    expect(out).toContain("bun is required");
  });

  test("includes fish profile auto-wiring", () => {
    const content = readFileSync(INSTALLER, "utf8");
    expect(content).toContain("fish)");
    expect(content).toContain("PROFILE=\"$HOME/.config/fish/config.fish\"");
    expect(content).toContain("if test -f \"$HOME/.shellshield/src/index.ts\"");
    expect(content).toContain("eval (bun run \"$HOME/.shellshield/src/index.ts\" --init)");
  });
});
