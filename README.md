# Block Destructive Commands

A Claude Code hook that blocks destructive file deletion commands and directs users to use `trash` instead. This ensures deleted files can be recovered from the system trash.

## Blocked Patterns

**Direct commands:**
- `rm`, `shred`, `unlink`

**Path variants:**
- `/bin/rm`, `/usr/bin/rm`, `./rm`

**Bypass attempts:**
- `command rm`, `env rm`, `\rm`
- `sudo rm`, `xargs rm`

**Subshell execution:**
- `sh -c "rm ..."`, `bash -c "rm ..."`, `zsh -c "rm ..."`

**Find commands:**
- `find . -delete`
- `find . -exec rm {} \;`

## Allowed Commands

- `git rm` (tracked by git, recoverable)
- `echo 'rm test'` (quoted strings are safe)
- All other commands

## Installation

### 1. Install Bun

```bash
curl -fsSL https://bun.sh/install | bash
```

### 2. Install the trash CLI

```bash
# macOS
brew install trash

# Linux / npm (cross-platform)
npm install -g trash-cli
```

### 3. Clone and install

```bash
git clone <repo-url>
cd claude-rm-rf
bun install
```

### 4. Configure Claude Code

Add to your `.claude/settings.json` or `.claude/settings.local.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bun run /path/to/claude-rm-rf/src/index.ts"
          }
        ]
      }
    ]
  }
}
```

Replace `/path/to/claude-rm-rf` with the actual path, or use `$CLAUDE_PROJECT_DIR` if installing per-project.

## Development

```bash
# Run tests (34 test cases)
bun test

# Build standalone executable (optional, ~60MB)
bun run build
```

## How It Works

The hook runs on every `Bash` tool call via the `PreToolUse` event:

1. Parses JSON input from Claude Code (stdin)
2. Strips quoted strings to avoid false positives
3. Checks for destructive patterns
4. Returns exit code 2 with error message if blocked
5. Returns exit code 0 to allow the command

### Pattern Detection

The hook detects destructive commands:
- At the start of a command or after shell operators (`&&`, `||`, `;`, `|`, `$(`, `` ` ``)
- Via absolute/relative paths (`/bin/rm`, `./rm`)
- Via shell builtins (`command rm`, `env rm`, `\rm`)
- Via privilege escalation (`sudo rm`, `xargs rm`)
- Via subshells (`sh -c`, `bash -c`, `zsh -c`)
- Via find (`-delete`, `-exec rm`)

Quoted strings are stripped first, so `echo 'rm file'` and `git commit -m "rm old"` are allowed.
