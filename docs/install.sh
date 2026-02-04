#!/usr/bin/env bash
set -euo pipefail

Color_Off=''
Red=''
Green=''
Dim=''
Bold_White=''
Bold_Green=''

if [[ -t 1 ]]; then
  Color_Off='\033[0m'
  Red='\033[0;31m'
  Green='\033[0;32m'
  Dim='\033[0;2m'
  Bold_White='\033[1m'
  Bold_Green='\033[1;32m'
fi

error() {
  echo -e "${Red}error${Color_Off}:" "$@" >&2
  exit 1
}

info() {
  echo -e "${Dim}$@ ${Color_Off}"
}

info_bold() {
  echo -e "${Bold_White}$@ ${Color_Off}"
}

success() {
  echo -e "${Green}$@ ${Color_Off}"
}

echo -e "${Bold_White}"
echo "🛡️  ShellShield Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${Color_Off}"

export PATH="$HOME/.bun/bin:$PATH"

command -v git >/dev/null 2>&1 || error "git is required"
command -v bun >/dev/null 2>&1 || error "bun is required (install: curl -fsSL https://bun.sh/install | bash)"

info "Checking requirements..."
success "✅ Dependencies found."

INSTALL_DIR="$HOME/.shellshield"
info "Installing to ${INSTALL_DIR}..."

if [ -d "$INSTALL_DIR/.git" ]; then
  info "Updating existing installation..."
  git -C "$INSTALL_DIR" fetch --quiet
  git -C "$INSTALL_DIR" reset --hard origin/main --quiet
elif [ -d "$INSTALL_DIR" ]; then
  info "Directory exists but is not a git repo. Backing up..."
  mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
  git clone --depth 1 https://github.com/hevlyo/ShellShield.git "$INSTALL_DIR" --quiet
else
  git clone --depth 1 https://github.com/hevlyo/ShellShield.git "$INSTALL_DIR" --quiet
fi

info "Installing project dependencies (this may take a moment)..."
cd "$INSTALL_DIR"

tmp_log=$(mktemp)
set +e
bun install --production --no-save --force 2>"$tmp_log"
install_status=$?
set -e

if [ $install_status -ne 0 ]; then
  if grep -q "lockfile had changes" "$tmp_log"; then
    error "bun lockfile is frozen. Update bun and retry (bun --version)."
  fi
  cat "$tmp_log" >&2
  error "Failed to install dependencies"
fi

success "✅ Installed successfully."

info "Configuring shell integration..."

USER_SHELL=$(basename "$SHELL")
PROFILE=""

case "$USER_SHELL" in
  zsh)
    PROFILE="$HOME/.zshrc"
    ;;
  bash)
    if [ -f "$HOME/.bashrc" ]; then
      PROFILE="$HOME/.bashrc"
    else
      PROFILE="$HOME/.bash_profile"
    fi
    ;;
  *)
    info "Unsupported shell detected: $USER_SHELL"
    PROFILE="$HOME/.profile"
    ;;
esac

HOOK_BEGIN="# ShellShield Hook"
HOOK_END="# ShellShield Hook End"
HOOK_SCRIPT="
$HOOK_BEGIN
if [ -f \"$HOME/.shellshield/src/index.ts\" ]; then
  eval \"\$(bun run \"$HOME/.shellshield/src/index.ts\" --init)\"
fi
$HOOK_END
"

if [ -f "$PROFILE" ]; then
  if grep -q "$HOOK_BEGIN" "$PROFILE"; then
    tmp_profile=$(mktemp)
    awk -v begin="$HOOK_BEGIN" -v end="$HOOK_END" '
      $0==begin {skip=1; next}
      $0==end {skip=0; next}
      !skip {print}
    ' "$PROFILE" > "$tmp_profile"
    cat "$tmp_profile" > "$PROFILE"
    rm "$tmp_profile"
  fi
  echo "$HOOK_SCRIPT" >> "$PROFILE"
  info "Hook added to $PROFILE"
else
  info "Could not find shell profile ($PROFILE)."
  info_bold "Add this manually to your config:"
  info_bold "$HOOK_SCRIPT"
fi

echo
success "🎉 Done! Restart your shell to activate ShellShield."
info_bold "Try running: rm -rf / (it will be blocked)"
