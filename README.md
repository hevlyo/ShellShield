# 🛡️ ShellShield

<p align="center">
  <strong>Stop accidental <code>rm -rf /</code> before it happens.</strong><br>
  The AI‑era security layer your terminal desperately needs.
</p>

<p align="center">
  <a href="#-quick-start">Get Started</a> •
  <a href="#-features">Features</a> •
  <a href="#-see-it-in-action">Demo</a> •
  <a href="#-performance">Performance</a> •
  <a href="#-configuration">Config</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Bun-1.0+-black?style=for-the-badge&logo=bun" alt="Bun">
  <img src="https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge" alt="Security Hardened">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License MIT">
</p>

---

## 🧐 Why ShellShield?

We've all been there. A misplaced space in `rm -rf / tmp/`, a copy‑paste from a malicious site, or a `curl | bash` that looked safe but used a **Cyrillic 'і'** instead of a Latin 'i'.

**Your browser catches these attacks. Your terminal doesn't. ShellShield does.**

ShellShield is a high‑performance, intelligent shell hook that tokenizes every command with a real shell parser to intercept destructive actions, homograph attacks, and terminal injections before they execute.

---

## 🎬 See It In Action

![ShellShield Demo](docs/demo.gif)

*ShellShield intercepting `rm -rf /` and blocking a homograph attack before execution.*

---

## ✨ Features

### 🛡️ Intelligent Destruction Blocking
- **Context‑Aware**: Uses `shell-quote` to distinguish `rm` as a command vs. a string in `grep`.
- **Recursive Analysis**: Dives into subshells (`sh -c "..."`) up to 5 levels.
- **Smart Suggestions**: Blocks `rm -rf folder/` and suggests `trash folder/`.
- **Critical Path Guard**: Prevents `mv`, `cp`, or `rm` on `/etc`, `/usr`, `/`, `C:\Windows`.

### 🔐 Advanced Security Guard
- **Interpreter RCE Defense**: Blocks `python -c "$(curl ...)"`, `node -e`, `ruby -e`, `perl`, `php`.
- **Homograph Defense**: Catches visually identical malicious domains (`іnstall.com`).
- **Injection Protection**: Blocks ANSI escapes and zero‑width characters.
- **Safe Pipe‑to‑Shell**: Flags `curl | bash` unless domain is trusted.
- **Encoded Payload Guard**: Blocks `base64 -d | sh` and `xxd -r -p | sh`.
- **Credential Guard**: Detects plain‑text passwords in URLs.

### 🚜 Terminal Governance
- **Git Workflow Safety**: Prevents deleting files with uncommitted changes.
- **Volume Threshold**: Intercepts accidental globs that target too many files.
- **Permissive Mode**: Log‑only mode for audits and CI.
- **Rotated Audit Log**: JSON trace in `~/.shellshield/audit.log` (auto‑rotated at 1MB).

---

## ⚡ Performance

- **28,884 ops/sec** benchmark throughput
- **~34.6µs latency per command** (imperceptible to humans)
- **96 tests** covering bypasses, edge cases, and advanced attacks

---

## 🔎 Why Trust This?

- **Local-only execution**: runs as a shell hook on your machine.
- **No daemon required**: checks happen at command time.
- **Transparent audit log**: records decisions to `~/.shellshield/audit.log`.
- **Open ruleset**: all detection logic lives in `src/parser/rules/`.
- **Extensive tests**: security and bypass cases covered in `tests/`.

---

## 🔐 Security

If you believe you have found a security issue, please report it privately.
Preferred: open a GitHub Security Advisory with clear reproduction steps and impact.
If private reporting is not possible, open a GitHub issue without exploit details.

---

## 🆚 Why Not Just Use `alias rm='rm -i'`?

| Feature | ShellShield | Basic Aliases | shellcheck |
|---|---|---|---|
| Context‑aware parsing | ✅ | ❌ | ⚠️ (static) |
| Homograph detection | ✅ | ❌ | ❌ |
| Subshell recursion | ✅ | ❌ | ❌ |
| Zero config needed | ✅ | ❌ | ❌ |
| AI agent safe | ✅ | ❌ | ❌ |
| Performance | **22.7k ops/sec** | N/A | ~10k ops/sec |

---

## 🚀 Quick Start

```bash
curl -fsSL https://hevlyo.github.io/ShellShield/install.sh -o /tmp/shellshield-install.sh
SHELLSHIELD_INSTALL_SHA256="363aeea624bf28102c7fc096239293d749f35ff9e868df1c1b12da571ef4a254" \
  bash /tmp/shellshield-install.sh
```

That’s it. ShellShield is now guarding your terminal.

SHA256 (install.sh): `363aeea624bf28102c7fc096239293d749f35ff9e868df1c1b12da571ef4a254`

Try:
```bash
rm -rf /tmp/test
```

### Uninstall

Remove the hook line from your shell config (`~/.zshrc` or `~/.bashrc`) and
restart your shell. Then delete local data:

```bash
rm -rf ~/.shellshield
```

<details>
<summary>📦 Manual Install</summary>

```bash
curl -fsSL https://bun.sh/install | bash
git clone https://github.com/hevlyo/ShellShield
cd ShellShield
bun install
bun run src/index.ts --init
```
</details>

---

## ⚙️ Configuration

ShellShield works out of the box. Create `.shellshield.json` to customize:

```json
{
  "blocked": ["rm", "shred", "custom-killer"],
  "allowed": ["ls", "cat"],
  "trustedDomains": ["github.com", "my-company.com"],
  "threshold": 100,
  "mode": "enforce",
  "maxSubshellDepth": 5,
  "contextPath": "~/.shellshield/shell-context.json"
}
```

### Modes
- `enforce` (default): blocks dangerous commands
- `permissive`: logs warnings but allows execution
- `interactive`: prompts for confirmation

### Environment Variables
- `SHELLSHIELD_THRESHOLD`: max files per delete (default: 50)
- `SHELLSHIELD_MODE`: set `permissive` or `interactive`
- `SHELLSHIELD_SKIP=1`: bypass checks for next command
- `SHELLSHIELD_MAX_SUBSHELL_DEPTH`: max nested `sh -c` analysis depth (default: 5)
- Recommended: keep between `3` and `6` for low overhead; raise only if you rely on deep nested shells.

### Shell Context (Aliases / Functions)

ShellShield analyzes the raw command string. Your shell aliases/functions are not automatically expanded.

Optional safety check (recommended if you use lots of aliases):
```bash
# Generate a snapshot of `type <cmd>` for common commands
bun run src/index.ts --snapshot

# Enable checks (blocks if a seemingly-safe command resolves to an alias/function
# that references a blocked primitive like rm/shred)
export SHELLSHIELD_CONTEXT_PATH="$HOME/.shellshield/shell-context.json"

# Optional: auto-refresh snapshot when your shell loads the hook
export SHELLSHIELD_AUTO_SNAPSHOT=1
```

You can also inspect your current shell resolution with:
```bash
bun run src/index.ts --doctor
```

### Examples

**For AI coding assistants**
```json
{ "mode": "interactive", "trustedDomains": ["github.com", "githubusercontent.com"] }
```

**For CI/CD pipelines**
```json
{ "mode": "permissive", "threshold": 1000 }
```

**For junior onboarding**
```json
{ "mode": "enforce", "blocked": ["rm", "mv", "dd", "shred"] }
```

---

## 🤝 Contributing

Want to add a new security rule? It’s fast:

1. Create a class in `src/parser/rules/` implementing `SecurityRule`
2. Add TSDoc explaining the threat
3. Write tests in `tests/`
4. Run `bun test` and `bun run benchmark.ts`

---

## 🤝 Credits & Inspiration

Originally inspired by [claude-rm-rf](https://github.com/zcaceres/claude-rm-rf) by Zach Caceres. Evolved into a complete security suite.

---

## 🚀 Ready to Protect Your Terminal?

⭐ **Star this repo** if ShellShield saved you from a disaster.

<p align="center">🛡️ Built for those who roll the boulder every day. Ship safe.</p>
