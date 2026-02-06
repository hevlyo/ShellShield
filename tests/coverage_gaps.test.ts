import { describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getConfiguration } from "../src/config";
import {
  findBlockedTokenInShellContext,
  getShellContextEntry,
  getShellContextSnapshotPath,
  readShellContextSnapshot,
  writeShellContextSnapshot,
} from "../src/shell-context";
import { logAudit } from "../src/audit";
import { checkDestructive } from "../src/parser/analyzer";
import { checkPipeToShell } from "../src/parser/pipe-checks";
import { checkBlockedCommand, checkFindCommand } from "../src/parser/command-checks";
import { DEFAULT_BLOCKED, DEFAULT_TRUSTED_DOMAINS } from "../src/constants";
import { hasHomograph, isTrustedDomain } from "../src/security/validators";
import { isCriticalPath, isSensitivePath } from "../src/security/paths";

function restoreEnv(prevEnv: NodeJS.ProcessEnv, prevCwd: string) {
  for (const key of Object.keys(process.env)) {
    if (!(key in prevEnv)) delete process.env[key];
  }
  for (const [key, value] of Object.entries(prevEnv)) {
    process.env[key] = value;
  }
  process.chdir(prevCwd);
}

describe("Coverage gap tests", () => {
  test("config handles invalid JSON and schema with DEBUG", () => {
    const prevEnv = { ...process.env };
    const prevCwd = process.cwd();
    const tempDir = mkdtempSync(join(tmpdir(), "shellshield-config-"));
    const configPath = join(tempDir, ".shellshield.json");
    writeFileSync(configPath, "{invalid json");

    try {
      process.env.INIT_CWD = tempDir;
      process.env.PWD = tempDir;
      process.env.DEBUG = "1";
      process.chdir(tempDir);

      const cfg = getConfiguration();
      expect(cfg.blocked.has("rm")).toBe(true);

      writeFileSync(configPath, JSON.stringify({ threshold: "bad" }));
      const cfg2 = getConfiguration();
      expect(cfg2.threshold).toBe(50);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
      restoreEnv(prevEnv, prevCwd);
    }
  });

  test("config sets context path and supports OPENCODE env overrides", () => {
    const prevEnv = { ...process.env };
    const prevCwd = process.cwd();
    const tempDir = mkdtempSync(join(tmpdir(), "shellshield-config-"));
    const configPath = join(tempDir, ".shellshield.json");
    writeFileSync(configPath, JSON.stringify({ contextPath: "/tmp/ctx.json" }));

    try {
      process.env.INIT_CWD = tempDir;
      process.env.PWD = tempDir;
      process.chdir(tempDir);
      delete process.env.SHELLSHIELD_CONTEXT_PATH;
      process.env.OPENCODE_BLOCK_COMMANDS = "destroy,obliterate";
      process.env.OPENCODE_ALLOW_COMMANDS = "harmless";

      const cfg = getConfiguration();
      expect(process.env.SHELLSHIELD_CONTEXT_PATH).toBe("/tmp/ctx.json");
      expect(cfg.blocked.has("destroy")).toBe(true);
      expect(cfg.allowed.has("harmless")).toBe(true);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
      restoreEnv(prevEnv, prevCwd);
    }
  });

  test("shell context read/write and lookup", () => {
    const prevEnv = { ...process.env };
    const prevCwd = process.cwd();
    const tempDir = mkdtempSync(join(tmpdir(), "shellshield-ctx-"));
    const snapshotPath = join(tempDir, "ctx.json");

    const missing = readShellContextSnapshot(join(tempDir, "missing.json"));
    expect(missing).toBeNull();

    const snapshot = {
      version: 1 as const,
      generatedAt: new Date().toISOString(),
      shell: "/bin/zsh",
      entries: {
        ls: { kind: "alias" as const, output: "ls is aliased to 'ls -G'", expansion: "ls -G" },
      },
    };

    writeShellContextSnapshot(snapshotPath, snapshot);
    process.env.SHELLSHIELD_CONTEXT_PATH = `  ${snapshotPath}  `;

    expect(getShellContextSnapshotPath()).toBe(snapshotPath);
    const entry = getShellContextEntry("ls");
    expect(entry?.kind).toBe("alias");

    const hit = findBlockedTokenInShellContext(
      { kind: "alias", output: "alias safe='rm -rf /'", expansion: "rm -rf /" },
      new Set(["rm"])
    );
    expect(hit).toBe("rm");

    // Default path call (may be null or valid depending on host)
    const maybeDefault = readShellContextSnapshot();
    expect(maybeDefault === null || maybeDefault.version === 1).toBe(true);

    const badVersionPath = join(tempDir, "bad-version.json");
    writeFileSync(badVersionPath, JSON.stringify({ version: 2, entries: {} }));
    expect(readShellContextSnapshot(badVersionPath)).toBeNull();

    const badJsonPath = join(tempDir, "bad-json.json");
    writeFileSync(badJsonPath, "{not json");
    expect(readShellContextSnapshot(badJsonPath)).toBeNull();

    rmSync(tempDir, { recursive: true, force: true });
    restoreEnv(prevEnv, prevCwd);
  });

  test("audit rotates when log grows beyond 1MB", () => {
    const prevEnv = { ...process.env };
    const prevCwd = process.cwd();
    const tempDir = mkdtempSync(join(tmpdir(), "shellshield-audit-"));
    const logPath = join(tempDir, "audit.log");
    writeFileSync(logPath, "a".repeat(1024 * 1024 + 5));

    process.env.SHELLSHIELD_AUDIT_DIR = tempDir;
    process.env.SHELLSHIELD_AUDIT_PATH = logPath;
    process.env.SHELLSHIELD_AUDIT_DISABLED = "0";

    logAudit("rm -rf /", { blocked: true, reason: "TEST", suggestion: "noop" }, { mode: "enforce" });

    expect(existsSync(logPath + ".1")).toBe(true);
    const content = readFileSync(logPath, "utf8").trim();
    expect(content.length).toBeGreaterThan(0);

    rmSync(tempDir, { recursive: true, force: true });
    restoreEnv(prevEnv, prevCwd);
  });

  test("audit rotate handles rename errors gracefully", () => {
    const prevEnv = { ...process.env };
    const prevCwd = process.cwd();
    const tempDir = mkdtempSync(join(tmpdir(), "shellshield-audit-"));
    const logPath = join(tempDir, "audit.log");
    writeFileSync(logPath, "a".repeat(1024 * 1024 + 5));

    process.env.SHELLSHIELD_AUDIT_DIR = tempDir;
    process.env.SHELLSHIELD_AUDIT_PATH = logPath;
    process.env.SHELLSHIELD_AUDIT_DISABLED = "0";

    try {
      chmodSync(tempDir, 0o500);
      logAudit("rm -rf /", { blocked: true, reason: "TEST", suggestion: "noop" }, { mode: "enforce" });
    } finally {
      chmodSync(tempDir, 0o700);
      rmSync(tempDir, { recursive: true, force: true });
      restoreEnv(prevEnv, prevCwd);
    }
  });

  test("audit catches rotation errors and warns on non-blocked reasons", () => {
    const prevEnv = { ...process.env };
    const prevCwd = process.cwd();
    const tempDir = mkdtempSync(join(tmpdir(), "shellshield-audit-"));
    const logPath = join(tempDir, "audit.log");
    writeFileSync(logPath, "ok\n");

    process.env.SHELLSHIELD_AUDIT_DIR = tempDir;
    process.env.SHELLSHIELD_AUDIT_PATH = logPath;
    process.env.SHELLSHIELD_AUDIT_DISABLED = "0";

    try {
      chmodSync(tempDir, 0o400);
      logAudit("ls", { blocked: false, reason: "TEST", suggestion: "noop" }, {});
    } finally {
      chmodSync(tempDir, 0o700);
    }

    logAudit("ls", { blocked: false, reason: "TEST", suggestion: "noop" }, {});
    const content = readFileSync(logPath, "utf8").trim();
    const lines = content.split("\n").reverse();
    const lastJson = lines.find((line) => line.trim().startsWith("{")) || "{}";
    const entry = JSON.parse(lastJson);
    expect(entry.decision).toBe("warn");

    rmSync(tempDir, { recursive: true, force: true });
    restoreEnv(prevEnv, prevCwd);
  });

  test("analyzer reports malformed syntax when parser throws", () => {
    const result = checkDestructive("echo ${", 0, {
      blocked: new Set(DEFAULT_BLOCKED),
      allowed: new Set<string>(),
      trustedDomains: DEFAULT_TRUSTED_DOMAINS,
      threshold: 50,
      mode: "enforce",
      customRules: [],
      maxSubshellDepth: 5,
    });
    expect(result.blocked).toBe(true);
    expect(result.reason).toBe("MALFORMED COMMAND SYNTAX");
  });

  test("pipe checks allow trusted domains directly", () => {
    const args = ["https://raw.githubusercontent.com/user/repo/main/install.sh"];
    const remaining = [
      "https://raw.githubusercontent.com/user/repo/main/install.sh",
      { op: "|" },
      "bash",
    ];
    const result = checkPipeToShell(args, remaining, ["raw.githubusercontent.com"]);
    expect(result).toBeNull();
  });

  test("validators cover greek and other scripts and invalid urls", () => {
    const mixed = hasHomograph("curl https://παράδειγμα.рф/script.sh");
    expect(mixed.detected).toBe(true);

    const other = hasHomograph("curl https://例子.测试/file.txt");
    expect(other.detected).toBe(false);

    expect(isTrustedDomain("not a url", ["example.com"])).toBe(false);
  });

  test("command checks cover dd safe path and find -exec benign", () => {
    const dd = checkBlockedCommand("dd", ["if=/dev/zero"], {
      blocked: new Set(DEFAULT_BLOCKED),
      threshold: 50,
    });
    expect(dd).toBeNull();

    const find = checkFindCommand(["-exec", "echo", "{}", ";"], new Set(["rm"]));
    expect(find).toBeNull();
  });

  test("path helpers cover windows normalization and non-sensitive path", () => {
    expect(isCriticalPath("C:Windows")).toBe(true);
    expect(isSensitivePath("/tmp/safe.txt")).toBe(false);
  });

  test("shell-quote handles env assignment and quoted args", () => {
    const result = checkDestructive("FOO=bar rm -- 'file name.txt'", 0, {
      blocked: new Set(DEFAULT_BLOCKED),
      allowed: new Set<string>(),
      trustedDomains: DEFAULT_TRUSTED_DOMAINS,
      threshold: 50,
      mode: "enforce",
      customRules: [],
      maxSubshellDepth: 5,
    });
    expect(result.blocked).toBe(true);
  });

  test("subshell detection supports fish and PowerShell flags", () => {
    const fish = checkDestructive("fish -c 'rm -rf /tmp/x'", 0, {
      blocked: new Set(DEFAULT_BLOCKED),
      allowed: new Set<string>(),
      trustedDomains: DEFAULT_TRUSTED_DOMAINS,
      threshold: 50,
      mode: "enforce",
      customRules: [],
      maxSubshellDepth: 5,
    });
    expect(fish.blocked).toBe(true);

    const pwsh = checkDestructive("pwsh -Command \"rm -rf /tmp/x\"", 0, {
      blocked: new Set(DEFAULT_BLOCKED),
      allowed: new Set<string>(),
      trustedDomains: DEFAULT_TRUSTED_DOMAINS,
      threshold: 50,
      mode: "enforce",
      customRules: [],
      maxSubshellDepth: 5,
    });
    expect(pwsh.blocked).toBe(true);
  });
});
