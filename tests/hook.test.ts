import { describe, test, expect } from "bun:test";
import { spawn } from "bun";
import { join } from "node:path";
import { checkDestructive } from "../src/parser/analyzer";
import { DEFAULT_BLOCKED, DEFAULT_TRUSTED_DOMAINS } from "../src/constants";

const PROJECT_ROOT = join(import.meta.dir, "..");
const HOOK_PATH = join(PROJECT_ROOT, "src", "index.ts");
const BUN_PATH = process.execPath;

const TEST_CONTEXT = {
  blocked: new Set(DEFAULT_BLOCKED),
  allowed: new Set<string>(),
  trustedDomains: DEFAULT_TRUSTED_DOMAINS,
  threshold: 50,
  mode: "enforce" as const,
  customRules: [],
  maxSubshellDepth: 5,
};

async function readStream(stream?: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!stream) return "";
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let result = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) result += decoder.decode(value, { stream: true });
    }
    result += decoder.decode();
    return result;
  } catch {
    return result;
  } finally {
    reader.releaseLock();
  }
}

async function runHook(command: string): Promise<{ exitCode: number; stderr: string }> {
  const input = JSON.stringify({ tool_input: { command } });

  const proc = spawn({
    cmd: [BUN_PATH, "run", HOOK_PATH],
    stdin: new Blob([input]),
    stderr: "pipe",
    stdout: "ignore",
    env: {
      ...process.env,
      BUN_COVERAGE: "0",
      SHELLSHIELD_AUDIT_DISABLED: "1",
      SHELLSHIELD_MODE: "enforce",
      SHELLSHIELD_SKIP: "0",
      INIT_CWD: PROJECT_ROOT,
      PWD: PROJECT_ROOT,
    },
    cwd: PROJECT_ROOT,
  });

  const exitCode = await proc.exited;
  const stderr = await readStream(proc.stderr);

  return { exitCode, stderr };
}

function analyze(command: string) {
  return checkDestructive(command, 0, TEST_CONTEXT);
}

describe("Commands that SHOULD be blocked", () => {
  test("rm file.txt", async () => {
    const result = analyze("rm file.txt");
    expect(result.blocked).toBe(true);
  });

  test("rm -rf directory/", async () => {
    const result = analyze("rm -rf directory/");
    expect(result.blocked).toBe(true);
  });

  test("rm -f *.log", async () => {
    const result = analyze("rm -f *.log");
    expect(result.blocked).toBe(true);
  });

  test("sudo rm file", async () => {
    const result = analyze("sudo rm file");
    expect(result.blocked).toBe(true);
  });

  test("cmd && rm file", async () => {
    const result = analyze("ls && rm file");
    expect(result.blocked).toBe(true);
  });

  test("cmd || rm file", async () => {
    const result = analyze("ls || rm file");
    expect(result.blocked).toBe(true);
  });

  test("cmd ; rm file", async () => {
    const result = analyze("ls ; rm file");
    expect(result.blocked).toBe(true);
  });

  test("cmd | xargs rm", async () => {
    const result = analyze("find . | xargs rm");
    expect(result.blocked).toBe(true);
  });

  test("shred secret.txt", async () => {
    const result = analyze("shred secret.txt");
    expect(result.blocked).toBe(true);
  });

  test("unlink file", async () => {
    const result = analyze("unlink file");
    expect(result.blocked).toBe(true);
  });
});

describe("Commands that SHOULD be allowed", () => {
  test("git rm file.ts", async () => {
    const result = analyze("git rm file.ts");
    expect(result.blocked).toBe(false);
  });

  test("ls -la", async () => {
    const result = analyze("ls -la");
    expect(result.blocked).toBe(false);
  });

  test("cat README.md", async () => {
    const result = analyze("cat README.md");
    expect(result.blocked).toBe(false);
  });

  test("npm install", async () => {
    const result = analyze("npm install");
    expect(result.blocked).toBe(false);
  });

  test("pnpm remove package", async () => {
    const result = analyze("pnpm remove package");
    expect(result.blocked).toBe(false);
  });

  test("echo 'rm test' (quoted)", async () => {
    const result = analyze("echo 'rm test'");
    expect(result.blocked).toBe(false);
  });

  test('echo "rm test" (double quoted)', async () => {
    const result = analyze('echo "rm test"');
    expect(result.blocked).toBe(false);
  });

  test("git commit -m 'rm old files'", async () => {
    const result = analyze("git commit -m 'rm old files'");
    expect(result.blocked).toBe(false);
  });

  test("grep 'rm' file.txt", async () => {
    const result = analyze("grep 'rm' file.txt");
    expect(result.blocked).toBe(false);
  });
});

describe("Bypass patterns that SHOULD be blocked", () => {
  test("/bin/rm file.txt (absolute path)", async () => {
    const result = analyze("/bin/rm file.txt");
    expect(result.blocked).toBe(true);
  });

  test("/usr/bin/rm -rf dir/ (absolute path)", async () => {
    const result = analyze("/usr/bin/rm -rf dir/");
    expect(result.blocked).toBe(true);
  });

  test("./rm file (relative path)", async () => {
    const result = analyze("./rm file");
    expect(result.blocked).toBe(true);
  });

  test("sh -c 'rm file.txt' (subshell)", async () => {
    const result = analyze("sh -c 'rm file.txt'");
    expect(result.blocked).toBe(true);
  });

  test("bash -c 'rm -rf dir/' (subshell)", async () => {
    const result = analyze("bash -c 'rm -rf dir/'");
    expect(result.blocked).toBe(true);
  });

  test("command rm file.txt (builtin bypass)", async () => {
    const result = analyze("command rm file.txt");
    expect(result.blocked).toBe(true);
  });

  test("env rm file.txt (env bypass)", async () => {
    const result = analyze("env rm file.txt");
    expect(result.blocked).toBe(true);
  });

  test("\\rm file.txt (backslash escape)", async () => {
    const result = analyze("\\rm file.txt");
    expect(result.blocked).toBe(true);
  });

  test("find . -delete", async () => {
    const result = analyze("find . -delete");
    expect(result.blocked).toBe(true);
  });

  test("find . -name '*.log' -delete", async () => {
    const result = analyze("find . -name '*.log' -delete");
    expect(result.blocked).toBe(true);
  });

  test("find . -exec rm {} \\;", async () => {
    const result = analyze("find . -exec rm {} \\;");
    expect(result.blocked).toBe(true);
  });

  test("sudo /bin/rm file", async () => {
    const result = analyze("sudo /bin/rm file");
    expect(result.blocked).toBe(true);
  });

  test("xargs /bin/rm", async () => {
    const result = analyze("find . | xargs /bin/rm");
    expect(result.blocked).toBe(true);
  });
});

describe("Edge cases", () => {
  test("empty command", async () => {
    const { exitCode } = await runHook("");
    expect(exitCode).toBe(0);
  });

  test("invalid JSON input exits 0", async () => {
    const proc = spawn({
      cmd: [BUN_PATH, "run", HOOK_PATH],
      stdin: new Blob(["not valid json"]),
      stderr: "pipe",
      stdout: "ignore",
      env: {
        ...process.env,
        SHELLSHIELD_AUDIT_DISABLED: "1",
        SHELLSHIELD_MODE: "enforce",
        SHELLSHIELD_SKIP: "0",
        INIT_CWD: PROJECT_ROOT,
        PWD: PROJECT_ROOT,
      },
      cwd: PROJECT_ROOT,
    });

    const exitCode = await proc.exited;
    expect(exitCode).toBe(0);
  });

  test("malformed substitution blocks", async () => {
    const { exitCode, stderr } = await runHook("rm ${}");
    expect(exitCode).toBe(2);
    expect(stderr).toContain("MALFORMED COMMAND SYNTAX");
  });
});
