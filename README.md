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

Generate the demo locally:
```bash
vhs demo.tape
```

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

- **22,700 ops/sec** benchmark throughput
- **~27µs latency per command** (imperceptible to humans)
- **96 tests** covering bypasses, edge cases, and advanced attacks

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
curl -fsSL https://hevlyo.github.io/ShellShield/install.sh | bash
```

That’s it. ShellShield is now guarding your terminal.

Try:
```bash
rm -rf /tmp/test
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
  "mode": "enforce"
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

## 🗺️ Roadmap

- [ ] Public docs site with rule reference
- [ ] Prebuilt binary releases
- [ ] Team dashboards for audit logs

---

## 🤝 Credits & Inspiration

Originally inspired by [claude-rm-rf](https://github.com/zcaceres/claude-rm-rf) by Zach Caceres. Evolved into a complete security suite.

---

## 🚀 Ready to Protect Your Terminal?

⭐ **Star this repo** if ShellShield saved you from a disaster.

<p align="center">🛡️ Built for those who roll the boulder every day. Ship safe.</p>
