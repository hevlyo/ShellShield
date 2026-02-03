# 🛡️ ShellShield

<p align="center">
  <strong>The ultimate safety shield for your terminal. Stop accidental destruction, before it happens.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Bun-1.0+-black?style=for-the-badge&logo=bun" alt="Bun">
  <img src="https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge" alt="Security Hardened">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License MIT">
</p>

---

## 🧐 Why ShellShield?

We've all been there. A misplaced space in `rm -rf / tmp/`, a copy-paste from a malicious site, or a `curl | bash` that looked safe but used a **Cyrillic 'і'** instead of a Latin 'i'. 

**Your browser catches these attacks. Your terminal doesn't. ShellShield does.**

ShellShield is a high-performance, intelligent shell hook that guards your gate. It tokenizes every command using a real shell parser to intercept destructive actions, homograph attacks, and terminal injections before they execute.

---

## ✨ Features that Make You Unstoppable

### 🛡️ Intelligent Destruction Blocking
-   **Context-Aware**: Uses `shell-quote` to understand if `rm` is a command or just a string in `grep`.
-   **Recursive Analysis**: Dives deep into subshells (`sh -c "..."`) up to 5 levels.
-   **Smart Suggestions**: Blocks `rm -rf folder/` and suggests `trash folder/` automatically.

### 🔐 Advanced Security Guard
-   **Homograph Defense**: Blocks visually identical malicious domains (e.g., `іnstall.com` vs `install.com`).
-   **Injection Protection**: Intercepts ANSI escapes and hidden zero-width characters that manipulate your terminal output.
-   **Safe Pipe-to-Shell**: Flags dangerous `curl | bash` patterns, while allowing trusted domains (GitHub, Docker, etc.).
-   **Command Substitution Guard**: Blocks `eval $(curl ...)` and `sh -c "$(curl ...)"` execution chains.
-   **Encoded Payload Guard**: Blocks `base64 -d | sh` and `xxd -r -p | sh` patterns.
-   **Download-and-Exec Guard**: Blocks `curl -o file && sh file` one-liners.
-   **Credential Guard**: Detects and blocks commands containing plain-text passwords in URLs.

### 🚜 Terminal Governance
-   **Critical Path Protection**: Blocks deletion of `/etc`, `/usr`, `C:\Windows`, and even `.git` folders.
-   **Git Workflow Safety**: Prevents deleting files with uncommitted changes.
-   **Volume Threshold**: Intercepts accidental globs that target hundreds of files at once.
-   **Security Audit Log**: Keeps a JSON trace of every blocked action in `~/.shellshield/audit.log`.

---

## 🚀 Quick Start

### 1. Install Bun
```bash
curl -fsSL https://bun.sh/install | bash
```

### 2. Install ShellShield Standalone
Works with **Zsh** and **Bash**. Just add this to your `.zshrc` or `.bashrc`:
```bash
# Add to your shell profile
eval "$(bun run /path/to/shellshield/src/index.ts --init)"
```

### 3. OpenCode Integration
Add as a `PreToolUse` hook in your `.opencode/settings.json`:
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

---

## ⚙️ Configuration (Governance as Code)

Customize your shield with a `.shellshield.json` file in your home or project directory:

```json
{
  "blocked": ["rm", "shred", "custom-killer"],
  "allowed": ["ls", "cat"],
  "trustedDomains": ["my-company.com", "github.com"],
  "threshold": 100
}
```

### Environment Variables
- `SHELLSHIELD_THRESHOLD`: Max files per delete (Default: 50).
- `SHELLSHIELD_SKIP=1`: Temporarily bypass all checks for the next command.

---

## 🛠️ Development & Testing

ShellShield is built with **TDD (Test-Driven Development)**. We have **80+ test cases** covering bypasses, security threats, and edge cases.

```bash
bun test
```

---

## 🤝 Credits & Inspiration
Originally inspired by the [claude-rm-rf](https://github.com/zcaceres/claude-rm-rf) project by Zach Caceres. Evolved into a complete security suite.

---
<p align="center">🛡️ Built for those who roll the boulder every day. Ship safe.</p>
