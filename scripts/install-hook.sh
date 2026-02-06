#!/bin/bash
set -e

echo "🔒 Installing ShellShield Pre-commit Hook..."

HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

if [[ ! -d ".git" ]]; then
  echo "❌ Not a git repository. Run 'git init' first."
  exit 1
fi

mkdir -p "$HOOK_DIR"

cat > "$HOOK_FILE" << 'EOF'
#!/bin/bash
set -e

if [[ "${SHELLSHIELD_SKIP:-}" == "1" ]]; then
  exit 0
fi

if [[ -x "$HOME/.bun/bin/bun" ]]; then
  BUN_BIN="$HOME/.bun/bin/bun"
elif command -v bun >/dev/null 2>&1; then
  BUN_BIN="bun"
else
  echo "ShellShield pre-commit: bun not found; skipping."
  exit 0
fi

if [[ -f "./src/index.ts" ]]; then
  CLI="./src/index.ts"
elif [[ -f "$HOME/.shellshield/src/index.ts" ]]; then
  CLI="$HOME/.shellshield/src/index.ts"
else
  echo "ShellShield pre-commit: shellshield not found; skipping."
  exit 0
fi

has_issues=0

while IFS= read -r line; do
  case "$line" in
    "+++"*|"@@"*|"diff "*|"index "*)
      continue
      ;;
  esac

  if [[ "$line" == "+"* ]]; then
    candidate="${line#+}"

    if [[ -z "${candidate//[[:space:]]/}" ]]; then
      continue
    fi

    if [[ "$candidate" =~ (rm|shred|unlink|wipe|srm|dd|curl|wget|bash|sh|zsh|python|node|perl|ruby|php|mv|cp) ]]; then
      if ! SHELLSHIELD_MODE=enforce "$BUN_BIN" run "$CLI" --check "$candidate" >/dev/null 2>&1; then
        echo "ShellShield pre-commit blocked line:"
        echo "  $candidate"
        has_issues=1
      fi
    fi
  fi
done < <(git diff --cached -U0 --no-color)

if [[ "$has_issues" -ne 0 ]]; then
  echo "Commit blocked by ShellShield."
  echo "Use SHELLSHIELD_SKIP=1 git commit to bypass."
  exit 1
fi

exit 0
EOF

chmod +x "$HOOK_FILE"
echo "✅ ShellShield Pre-commit Hook installed!"
