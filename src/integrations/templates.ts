export const SHELL_TEMPLATES: Record<string, string> = {
  zsh: `
# ShellShield Zsh Integration
_shellshield_accept_line() {
    if [ -n "$SHELLSHIELD_SKIP" ]; then
        zle .accept-line
        return
    fi
    if command -v bun >/dev/null 2>&1; then
        bun run "{{CLI_PATH}}" --check "$BUFFER" || return $?
    fi
    zle .accept-line
}
zle -N accept-line _shellshield_accept_line
autoload -Uz add-zsh-hook
add-zsh-hook -d preexec _shellshield_preexec 2>/dev/null
unfunction _shellshield_preexec 2>/dev/null

# Optional: auto-refresh alias/function context snapshot
if [ "$SHELLSHIELD_AUTO_SNAPSHOT" = "1" ]; then
    if [ -z "$SHELLSHIELD_CONTEXT_PATH" ]; then
        export SHELLSHIELD_CONTEXT_PATH="$HOME/.shellshield/shell-context.json"
    fi
    if [ -z "$_SHELLSHIELD_CONTEXT_SYNCED" ]; then
        export _SHELLSHIELD_CONTEXT_SYNCED=1
        if command -v bun >/dev/null 2>&1; then
            bun run "{{CLI_PATH}}" --snapshot --out "$SHELLSHIELD_CONTEXT_PATH" >/dev/null 2>&1
        fi
    fi
fi

# Optional: bracketed paste safety
if [ "$SHELLSHIELD_PASTE_HOOK" = "1" ]; then
    _shellshield_bracketed_paste() {
        local before_left="$LBUFFER"
        local before_right="$RBUFFER"
        zle .bracketed-paste
        local pasted="\${LBUFFER#$before_left}"
        if [ -n "$pasted" ]; then
            if command -v bun >/dev/null 2>&1; then
                printf "%s" "$pasted" | bun run "{{CLI_PATH}}" --paste || {
                    LBUFFER="$before_left"
                    RBUFFER="$before_right"
                    return 1
                }
            fi
        fi
    }
    zle -N bracketed-paste _shellshield_bracketed_paste
fi
`,
  fish: `
# ShellShield Fish Integration
function __shellshield_preexec --on-event fish_preexec
    if test -n "$SHELLSHIELD_SKIP"
        return
    end
    if type -q bun
        set -l cmd $argv
        if test (count $cmd) -gt 1
            set -l cmd (string join " " -- $cmd)
        end
        if test -n "$cmd"
            bun run "{{CLI_PATH}}" --check "$cmd"; or return $status
        end
    end
end

# Optional: auto-refresh alias/function context snapshot
if test "$SHELLSHIELD_AUTO_SNAPSHOT" = "1"
    if test -z "$SHELLSHIELD_CONTEXT_PATH"
        set -gx SHELLSHIELD_CONTEXT_PATH "$HOME/.shellshield/shell-context.json"
    end
    if test -z "$_SHELLSHIELD_CONTEXT_SYNCED"
        set -gx _SHELLSHIELD_CONTEXT_SYNCED 1
        if type -q bun
            bun run "{{CLI_PATH}}" --snapshot --out "$SHELLSHIELD_CONTEXT_PATH" >/dev/null 2>&1
        end
    end
end
`,
  bash: `
# ShellShield Bash Integration
_shellshield_bash_preexec() {
    if [ -n "$SHELLSHIELD_SKIP" ]; then return 0; fi
    if command -v bun >/dev/null 2>&1; then
        bun run "{{CLI_PATH}}" --check "$BASH_COMMAND" || return $?
    fi
}
trap '_shellshield_bash_preexec' DEBUG

# Optional: auto-refresh alias/function context snapshot
if [ "$SHELLSHIELD_AUTO_SNAPSHOT" = "1" ]; then
    if [ -z "$SHELLSHIELD_CONTEXT_PATH" ]; then
        export SHELLSHIELD_CONTEXT_PATH="$HOME/.shellshield/shell-context.json"
    fi
    if [ -z "$_SHELLSHIELD_CONTEXT_SYNCED" ]; then
        export _SHELLSHIELD_CONTEXT_SYNCED=1
        if command -v bun >/dev/null 2>&1; then
            bun run "{{CLI_PATH}}" --snapshot --out "$SHELLSHIELD_CONTEXT_PATH" >/dev/null 2>&1
        fi
    fi
fi
`,
  powershell: `
# ShellShield PowerShell Integration
if (Get-Command Set-PSReadLineKeyHandler -ErrorAction SilentlyContinue) {
  Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
    param($key, $arg)
    if ($env:SHELLSHIELD_SKIP) {
      [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
      return
    }
    if (Get-Command bun -ErrorAction SilentlyContinue) {
      $line = $null
      $cursor = $null
      [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
      if ($line) {
        bun run "{{CLI_PATH}}" --check $line
        if ($LASTEXITCODE -ne 0) { return }
      }
    }
    [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
  }
} else {
  Write-Host "PSReadLine not available; cannot hook Enter key."
}
`,
};
