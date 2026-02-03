# 🛡️ ShellShield

**The ultimate safety shield for your terminal.**

ShellShield is a high-performance OpenCode hook that blocks destructive commands, protects critical system paths, and ensures your Git workflow remains safe. It's the governance layer your terminal deserves.

> **Note:** ShellShield provides robust protection but is not a substitute for regular backups. Use it as your first line of defense.

## ✨ Features

-   🌐 **Standalone Mode**: Use ShellShield in any terminal (Zsh/Bash) with easy integration hooks.
-   🛡️ **Homograph Attack Protection**: Detects and blocks visually similar malicious domains (e.g., Cyrillic 'i' replacing Latin 'i') used in `curl` or `wget`.
-   💉 **Terminal Injection Defense**: Intercepts ANSI escape sequences and hidden zero-width characters that can manipulate terminal display or hide malicious code.
-   🔗 **Pipe-to-Shell Guard**: Flags dangerous `curl | bash` or `wget | sh` patterns, with a smart **Trusted Domains Allowlist** (allows GitHub, Docker, Rustup, etc. by default).
-   🔒 **Insecure Transport Block**: Blocks piping to shell when using plain HTTP or when certificate validation is disabled (`-k`, `--insecure`).
-   🕵️ **Credential Exposure Detection**: Automatically flags URLs containing sensitive credentials (e.g., `https://user:password@host`).
-   🛡️ **Critical Path Protection**: Automatically blocks deletion of system directories like `/etc`, `/usr`, and project-critical folders like `.git`. Supports Linux, macOS, and Windows.
-   **Commit First, Delete Later**: Blocks deletion of files with uncommitted Git changes to prevent data loss.
-   🚀 **Volume Threshold Protection**: Intercepts commands targeting a large number of files (default > 50) to prevent globbing accidents.
-   📜 **Security Audit Log**: Keeps a JSON-formatted log of all intercepted actions in `~/.shellshield/audit.log`.
-   🧠 **Recursive Subshell Analysis**: Dives deep into nested subshells (`sh -c "bash -c '...' "`) to find hidden threats.
-   **Variable Expansion Tracking**: Detects bypass attempts using variables like `CMD=rm; $CMD file`.

## ⚙️ Configuration

ShellShield can be configured via environment variables or a `.shellshield.json` file in your project or home directory.

### .shellshield.json

```json
{
  "blocked": ["rm", "shred", "custom-command"],
  "allowed": ["ls", "cat"],
  "trustedDomains": ["my-company.com", "github.com"],
  "threshold": 100
}
```

### Environment Variables

- `OPENCODE_BLOCK_COMMANDS`: Comma-separated list of additional commands to block.
- `OPENCODE_ALLOW_COMMANDS`: Comma-separated list of commands to explicitly allow.
- `SHELLSHIELD_THRESHOLD`: Number of files allowed in a single command before blocking (default: 50).
- `SHELLSHIELD_SKIP`: Set to `1` to temporarily bypass checks (e.g., `SHELLSHIELD_SKIP=1 rm -rf /tmp/test`).

## 🚀 Installation

### General Shell Integration (Standalone)

Add ShellShield to your terminal regardless of OpenCode:

1.  **Install Bun**: `curl -fsSL https://bun.sh/install | bash`
2.  **Add to shell profile** (`.zshrc` or `.bashrc`):
    ```bash
    eval "$(bun run /path/to/shellshield/src/index.ts --init)"
    ```

### OpenCode Hook Integration

Example in `.opencode/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bun run /path/to/shellshield/src/index.ts"
          }
        ]
      }
    ]
  }
}
```

## 🛠️ Development

```bash
# Run the full test suite (71 test cases)
bun test
```

## 🧠 How It Works

ShellShield leverages the `shell-quote` library to accurately tokenize incoming Bash commands. Unlike simple regex-based blockers, ShellShield understands command positions, operators, and environment variables, providing a professional-grade security layer.

---
*Originally inspired by the claude-rm-rf project by Zach Caceres.*
