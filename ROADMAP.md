# ShellShield Roadmap

**Last updated:** February 4, 2026

## Vision

ShellShield is the **filesystem guardian** for the AI era. While tools like Tirith focus on supply chain security (URLs, downloads), ShellShield protects what matters most: **your files**.

**Core differentiators:**
- Blocks destructive commands (`rm -rf /`, massive globs, critical paths)
- Recursive subshell analysis (up to 5 levels deep)
- Alias/function masking detection
- Git-aware safety (uncommitted changes protection)
- Custom regex rules with user-defined suggestions
- Zero config, ~32.8µs latency, 30k+ ops/sec

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Done |
| 🚧 | In progress |
| ⏳ | Planned |
| 💡 | Idea / RFC |
| 🔥 | High priority |
| 🎯 | Strategic (competitive advantage) |

---

## Completed

- ✅ Core analysis engine with Strategy Pattern (pluggable rules)
- ✅ Homograph attack detection (Cyrillic, Greek lookalikes)
- ✅ Terminal injection protection (ANSI escapes, zero-width chars)
- ✅ Pipe-to-shell detection (`curl | bash`, `wget | sh`)
- ✅ Interpreter RCE defense (`python -c`, `node -e`, `ruby -e`, `perl -e`)
- ✅ Critical path protection (`/etc`, `/usr`, `/`, `C:\Windows`)
- ✅ Subshell recursive analysis (configurable depth)
- ✅ Shell context snapshot (`--snapshot` for aliases/functions)
- ✅ Custom regex rules via config
- ✅ Three modes: `enforce`, `permissive`, `interactive`
- ✅ Rotated audit log (`~/.shellshield/audit.log`, 1MB rotation)
- ✅ SHA256 + GPG-signed installer
- ✅ npm/bunx publishing (`@shellshield/shellshield`)
- ✅ CI/CD with GitHub Actions + Dependabot
- ✅ 117 tests, 30k+ ops/sec benchmark
- ✅ "Why Trust This?" section in README

---

## v1.1 → v1.2 (Current Focus)

**Goal:** First public release, initial traction, reduce adoption friction.

### Release & Distribution 🔥
- ⏳ Publish v1.1.0 release tag with changelog on GitHub
- ⏳ Homebrew tap (`brew install shellshield`) 🎯
- ⏳ Prebuilt binaries (Linux x64, macOS arm64) via GitHub Releases

### Shell Support 🔥
- ⏳ Fish shell support (#3) 🎯
- ⏳ Seamless hook auto-init (detect shell, suggest config)

### Outreach
- ⏳ Launch post: X/Reddit/HN with demo GIFs
- ⏳ TabNews post (PT-BR community)

---

## v1.2 → v2.0 (Competitive Parity)

**Goal:** Match Tirith's distribution reach, add unique CLI features.

### Distribution 🎯
- ⏳ AUR package (Arch Linux)
- ⏳ Nix flake
- ⏳ apt/dpkg (.deb) for Debian/Ubuntu
- ⏳ dnf/rpm for Fedora/RHEL
- ⏳ Scoop bucket (Windows)
- ⏳ Docker image (`ghcr.io/hevlyo/shellshield`)
- ⏳ asdf plugin

### CLI Enhancements 🎯
- ⏳ `shellshield run <url>` — safe `curl | bash` replacement (download → review → confirm)
- ⏳ `shellshield diff <url>` — byte-level homograph comparison
- ⏳ `shellshield why` — explain last triggered rule
- ⏳ `shellshield receipt` — audit trail for executed scripts

### New Protections
- ⏳ Dotfile attack detection (writes to `~/.bashrc`, `~/.ssh/authorized_keys`)
- ⏳ `curl -k` / disabled TLS verification warning
- ⏳ HTTP (non-HTTPS) pipe-to-shell blocking
- ⏳ Git clone typosquat detection
- ⏳ Docker untrusted registry warning
- ⏳ Bidi override detection (RTL text tricks)

### AI Integration 🎯
- ⏳ Cursor/Claude/Aider integration docs
- ⏳ MCP server for AI agents
- ⏳ Pre-execution preview mode for AI-generated commands

### Configuration
- ⏳ Config presets: `dev`, `prod`, `paranoid`
- ⏳ `allow_bypass: false` for enterprise lockdown
- ⏳ YAML config support (alongside JSON)

### Documentation
- ⏳ Public docs site (Docusaurus or MkDocs)
- ⏳ Threat model documentation
- ⏳ Cookbook with policy examples
- ⏳ Troubleshooting guide
- ⏳ Uninstall guide per shell/package manager

---

## v2.x+ (Long Term)

**Goal:** Enterprise features, ecosystem expansion.

### Enterprise
- 💡 Team dashboards for centralized audit logs
- 💡 Self-hosted audit server
- 💡 SSO/LDAP integration for policy management
- 💡 Compliance reports (SOC2, HIPAA)

### Advanced Detection
- 💡 LLM-assisted prompt analysis (detect jailbreaks)
- 💡 Learning mode (auto-build allowlists from user behavior)
- 💡 Fuzz testing infrastructure

### Integrations
- 💡 VSCode/Cursor extension (pre-execution shield)
- 💡 1Password/GitGuardian for secrets in commands
- 💡 Slack/Discord notifications for blocked commands

### Performance
- 💡 Consider Rust/Go rewrite for native binary (eliminate Bun dependency)
- 💡 WASM build for browser-based analysis

---

## 2026 Goals

| Metric | Target |
|--------|--------|
| GitHub stars | 500+ |
| Contributors | 10+ |
| Package managers | 5+ (npm, Homebrew, AUR, apt, Nix) |
| AI tool integrations | 2+ (Cursor, Claude, or Aider) |
| Test coverage | 90%+ |

---

## Competitive Positioning

```
ShellShield vs Tirith — complementary, not competing

┌─────────────────────────────────────────────────────────┐
│                    TIRITH                               │
│  • Supply chain security (URLs, TLS, downloads)         │
│  • 30 rules across 7 categories                         │
│  • Rust binary, mature distribution                     │
│  • AGPL-3.0 license                                     │
└─────────────────────────────────────────────────────────┘
                         │
                         │ (complementary)
                         │
┌─────────────────────────────────────────────────────────┐
│                  SHELLSHIELD                            │
│  • Filesystem protection (rm, mv, cp, globs)            │
│  • Subshell recursion, alias detection                  │
│  • Custom rules, git-aware safety                       │
│  • MIT license, AI-first focus                          │
└─────────────────────────────────────────────────────────┘
```

**Our unique strengths (Tirith doesn't have):**
- `rm -rf /` and critical path protection
- Massive glob interception (threshold-based)
- Subshell recursive analysis (5 levels)
- Alias/function masking detection
- Git uncommitted changes protection
- Custom regex rules with suggestions
- MIT license (more permissive)

---

## Contributing

### Current Priorities
1. 🔥 Homebrew tap
2. 🔥 Fish shell support
3. 🔥 `shellshield run <url>` command

### How to Help
- Check issues labeled `help wanted` or `good first issue`
- New ideas? Open a discussion or issue with `[RFC]` prefix
- Security issues? See `SECURITY.md` for responsible disclosure

### Adding a New Rule
1. Create a class in `src/parser/rules/` implementing `SecurityRule`
2. Set `phase: "pre"` (string checks) or `phase: "post"` (AST checks)
3. Add TSDoc explaining the threat
4. Write tests in `tests/`
5. Run `bun test` and `bun run benchmark.ts`

---

## Acknowledgments

- [claude-rm-rf](https://github.com/zcaceres/claude-rm-rf) by Zach Caceres — original inspiration for the project
- [Tirith](https://github.com/sheeki03/tirith) by @sheeki03 — inspiration for `curl | bash` protection after seeing their X post; great work on supply chain security
