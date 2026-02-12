const BYPASS_CASE = `
    case "\\$SHELLSHIELD_SKIP" in
        1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn]|[Ee][Nn][Aa][Bb][Ll][Ee]|[Ee][Nn][Aa][Bb][Ll][Ee][Dd])`;

const AUTO_REFRESH_TEMPLATE = `
# Optional: auto-refresh alias/function context snapshot
if [ "\\$SHELLSHIELD_AUTO_SNAPSHOT" = "1" ]; then
    if [ -z "\\$SHELLSHIELD_CONTEXT_PATH" ]; then
        export SHELLSHIELD_CONTEXT_PATH="\\$HOME/.shellshield/shell-context.json"
    fi
    if [ -z "\\$_SHELLSHIELD_CONTEXT_SYNCED" ]; then
        export _SHELLSHIELD_CONTEXT_SYNCED=1
        if command -v bun >/dev/null 2>&1; then
            bun run "{{CLI_PATH}}" --snapshot --out "\\$SHELLSHIELD_CONTEXT_PATH" >/dev/null 2>&1
        fi
    fi
fi`;

export const SHELL_TEMPLATES: Record<string, string> = {
  zsh: `
# ShellShield Zsh Integration
_shellshield_accept_line() {
    # Check for valid bypass values
\${BYPASS_CASE}
            zle .accept-line
            return
            ;;
    esac
    if command -v bun >/dev/null 2>&1; then
        bun run "{{CLI_PATH}}" --check "\\$BUFFER" || return \\$?
    fi
    zle .accept-line
}
zle -N accept-line _shellshield_accept_line
autoload -Uz add-zsh-hook
add-zsh-hook -d preexec _shellshield_preexec 2>/dev/null
unfunction _shellshield_preexec 2>/dev/null
\${AUTO_REFRESH_TEMPLATE}

# Optional: bracketed paste safety
if [ "\\$SHELLSHIELD_PASTE_HOOK" = "1" ]; then
    _shellshield_bracketed_paste() {
        local before_left="\\$LBUFFER"
        local before_right="\\$RBUFFER"
        zle .bracketed-paste
        local pasted="\\\${LBUFFER#\\"\\$before_left\\"}"
        if [ -n "\\$pasted" ]; then
            if command -v bun >/dev/null 2>&1; then
                printf "%s" "\\$pasted" | bun run "{{CLI_PATH}}" --paste || {
                    LBUFFER="\\$before_left"
                    RBUFFER="\\$before_right"
                    return 1
                }
            fi
        fi
    }
    zle -N bracketed-paste _shellshield_bracketed_paste
fi
`,
  bash: `
# ShellShield Bash Integration
_shellshield_bash_preexec() {
    # Check for valid bypass values
\${BYPASS_CASE}
            return 0
            ;;
    esac
    if command -v bun >/dev/null 2>&1; then
        bun run "{{CLI_PATH}}" --check "\\$BASH_COMMAND" || return \\$?
    fi
}
trap '_shellshield_bash_preexec' DEBUG
\${AUTO_REFRESH_TEMPLATE}
`,
  fish: `
# ShellShield Fish Integration
function __shellshield_preexec --on-event fish_preexec
    # Check for valid bypass values (case-insensitive)
    set -l skip_lower (string lower "\\$SHELLSHIELD_SKIP")
    if contains "\\$skip_lower" 1 true yes on enable enabled
        return
    end
    if type -q bun
        set -l cmd \\$argv
        if test (count \\$cmd) -gt 1
            set -l cmd (string join " " -- \\$cmd)
        end
        if test -n "\\$cmd"
            bun run "{{CLI_PATH}}" --check "\\$cmd"; or return \\$status
        end
    end
end

# Optional: auto-refresh alias/function context snapshot
if test "\\$SHELLSHIELD_AUTO_SNAPSHOT" = "1"
    if test -z "\\$SHELLSHIELD_CONTEXT_PATH"
        set -gx SHELLSHIELD_CONTEXT_PATH "\\$HOME/.shellshield/shell-context.json"
    end
    if test -z "\\$_SHELLSHIELD_CONTEXT_SYNCED"
        set -gx _SHELLSHIELD_CONTEXT_SYNCED 1
        if type -q bun
            bun run "{{CLI_PATH}}" --snapshot --out "\\$SHELLSHIELD_CONTEXT_PATH" >/dev/null 2>&1
        end
    end
end
`,
  powershell: `
# ShellShield PowerShell Integration
if (Get-Command Set-PSReadLineKeyHandler -ErrorAction SilentlyContinue) {
  Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
    param(\\$key, \\$arg)
    # Check for valid bypass values (case-insensitive)
    \\$validBypassValues = @("1", "true", "yes", "on", "enable", "enabled")
    if (\\$validBypassValues -contains \\$env:SHELLSHIELD_SKIP.ToLower()) {
      [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
      return
    }
    if (Get-Command bun -ErrorAction SilentlyContinue) {
      \\$line = \\$null
      \\$cursor = \\$null
      [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]\\$line, [ref]\\$cursor)
      if (\\$line) {
        bun run "{{CLI_PATH}}" --check \\$line
        if (\\$LASTEXITCODE -ne 0) { return }
      }
    }
    [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
  }
} else {
  Write-Host "PSReadLine not available; cannot hook Enter key."
}
`,
};