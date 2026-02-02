# 🛡️ ShellShield

**The ultimate safety shield for your terminal.**

ShellShield is a high-performance OpenCode hook that blocks destructive commands, protects critical system paths, and ensures your Git workflow remains safe. It's the governance layer your terminal deserves.

> **Note:** ShellShield provides robust protection but is not a substitute for regular backups. Use it as your first line of defense.

## ✨ Features

-   🛡️ **Critical Path Protection**: Automatically blocks deletion of system directories like `/etc`, `/usr`, and project-critical folders like `.git`.
-   **Commit First, Delete Later**: Blocks deletion of files with uncommitted Git changes to prevent data loss.
-   🚀 **Volume Threshold Protection**: Intercepts commands targeting a large number of files (default > 50) to prevent globbing accidents.
-   📜 **Security Audit Log**: Keeps a JSON-formatted log of all intercepted actions in `~/.shellshield/audit.log`.
-   🧠 **Recursive Subshell Analysis**: Dives deep into nested subshells (`sh -c "bash -c '...' "`) to find hidden threats.
-   **Variable Expansion Tracking**: Detects bypass attempts using variables like `CMD=rm; $CMD file`.

## 🛡️ Blocked Patterns

**Direct commands:**
- `rm`, `shred`, `unlink`, `wipe`, `srm`
- `dd` with `of=` (output file)

**Path variants:**
- `/bin/rm`, `/usr/bin/rm`, `./rm`

**Bypass attempts:**
- `command rm`, `env rm`, `\rm`
- `sudo rm`, `xargs rm`
- Variable expansion: `CMD=rm; $CMD file`

**Subshell execution:**
- `sh -c "rm ..."`, `bash -c "rm ..."`, `zsh -c "rm ..."` (recursive up to 5 levels)

**Find commands:**
- `find . -delete`
- `find . -exec rm {} \;`

## ✅ Allowed Commands

- `git rm` (tracked by git, recoverable)
- `echo 'rm test'` (quoted strings are safe)
- Commands that don't match destructive patterns

## ⚙️ Configuration

Customize ShellShield using environment variables in your OpenCode settings:

- `OPENCODE_BLOCK_COMMANDS`: Comma-separated list of additional commands to block.
- `OPENCODE_ALLOW_COMMANDS`: Comma-separated list of commands to explicitly allow.
- `SHELLSHIELD_THRESHOLD`: Number of files allowed in a single command before blocking (default: 50).

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
            "command": "bun run /path/to/shellshield/src/index.ts",
            "env": {
              "SHELLSHIELD_THRESHOLD": "20",
              "OPENCODE_BLOCK_COMMANDS": "custom-delete"
            }
          }
        ]
      }
    ]
  }
}
```

## 🚀 Installation

### 1. Install Bun

```bash
curl -fsSL https://bun.sh/install | bash
```

### 2. Install the trash CLI

ShellShield suggests using `trash` for safe deletions.

```bash
# macOS
brew install trash

# Linux / npm (cross-platform)
npm install -g trash-cli
```

### 3. Clone and install ShellShield

```bash
git clone https://github.com/your-user/shellshield.git
cd shellshield
bun install
```

## 🛠️ Development

```bash
# Run the full test suite (49 test cases)
bun test
```

## 🧠 How It Works

ShellShield leverages the `shell-quote` library to accurately tokenize incoming Bash commands. Unlike simple regex-based blockers, ShellShield understands command positions, operators, and environment variables, providing a professional-grade security layer.

---
*Originally inspired by the claude-rm-rf project by Zach Caceres.*
