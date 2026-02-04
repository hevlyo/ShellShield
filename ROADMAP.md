# ShellShield Roadmap

**Última atualização:** 04 de fevereiro de 2026  
**Visão geral:** Tornar o terminal seguro na era de IA coding assistants, com overhead mínimo e foco em vibecoders / power users.  
Prioridade: Alta (H) / Média (M) / Baixa (L)  
Status: ✅ Feito | 🚧 Em progresso | ⏳ Planejado | ❓ Ideia

## Próximos passos
- Publicar v0.1.0-beta com notas de release no GitHub
- Adicionar checksum SHA256 + verificação no install.sh ✅
- Publicar no npm/Bun (`bun publish`)
- Post no TabNews + divulgação inicial (linkando este ROADMAP)
- Adicionar GitHub Actions para `bun test` + badge de CI ✅
- Configurar Dependabot para dependências Bun/TS ✅

## Visão de curto prazo (Q1-Q2 2026) — v0.5 a v1.0
Foco: Estabilizar core, ganhar tração inicial, reduzir fricção de adoção.

- [x] Hardening do installer + git hook funcional ✅
- [x] Suporte opt-in a aliases/functions via snapshot in-memory (`contextPath` + `--snapshot`) ✅
- [x] Testes E2E estabilizados e demo assets via vhs ✅
- [ ] Publicar primeira release tag (v0.1.0 beta) com notas de release no GitHub
- [ ] Integração seamless com bash/zsh (hook init automático)
- [x] Seção "Why Trust This?" no README ✅
- [x] GPG-signed install.sh ✅
- [ ] Badges: stars goal (CI ✅, coverage ✅, dependabot ✅)
- [ ] Post inicial em X/Reddit/HN com demo GIFs

## Médio prazo (Q2-Q3 2026) — v1.0 a v2.0
Foco: Features que diferenciam + expansão de shells/ambientes.

- [ ] Suporte oficial a fish shell (#3)
- [ ] Modo Windows (via WSL ou native se viável)
- [ ] Public docs site (Docusaurus ou MkDocs) com rule reference completa
- [ ] Prebuilt binaries (via GitHub Releases: Linux/macOS/arm64)
- [ ] npm/Bun publish global (`bunx shellshield` ou `npm i -g shellshield`)
- [ ] Homebrew tap oficial
- [ ] Integração com tools AI: preview de comandos no Cursor/Claude/Aider
- [ ] Alertas desktop (notify-send, terminal bell custom)
- [ ] Config presets: "dev", "prod", "paranoid"

## Longo prazo (Q4 2026+) — v2.x+
Foco: Enterprise/team features + ecossistema.

- [ ] Team dashboards para audit logs (centralizado, talvez via self-hosted server)
- [ ] Análise de prompts maliciosos (regex + LLM lightweight para detectar jailbreaks)
- [ ] Plugin VSCode/Cursor que injeta ShellShield antes de executar
- [ ] Suporte a mais interpretadores (ruby -e, perl -e, etc.)
- [ ] Modo "learning" (aprende allowlists do usuário ao longo do tempo)
- [ ] Integração com 1Password/GitGuardian para segredos em comandos

## Metas 2026
- 100+ stars
- 10+ contributors
- Uso real em workflows AI (Cursor/Claude/Aider)
- Integrações com pelo menos 2 tools populares

## Como contribuir / Prioridades atuais
- Veja issues com label `help wanted` ou `good first issue`
- Ideias novas? Abra discussion ou issue com [RFC] no título
- Quer priorizar algo?
