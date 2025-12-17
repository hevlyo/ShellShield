# Block Destructive Commands

A Claude Code hook that blocks destructive file deletion commands (`rm`, `shred`, `unlink`) and directs users to use `trash` instead. This ensures deleted files can be recovered from the system trash.

## Blocked Commands

- `rm` / `rm -rf` / `rm -f`
- `shred`
- `unlink`

## Allowed Commands

- `git rm` (tracked by git, recoverable)
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

### 3. Install dependencies

```bash
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
            "command": "bun run $CLAUDE_PROJECT_DIR/src/index.ts"
          }
        ]
      }
    ]
  }
}
```

## Development

```bash
# Run tests
bun test

# Build standalone executable (optional, ~60MB)
bun run build
```

## How It Works

The hook runs on every `Bash` tool call via the `PreToolUse` event:

1. Parses JSON input from Claude Code (stdin)
2. Strips quoted strings to avoid false positives (e.g., `echo 'rm test'`)
3. Checks for destructive patterns at command start or after shell operators (`&&`, `||`, `;`, `|`)
4. Returns exit code 2 with error message if blocked
5. Returns exit code 0 to allow the command

### Pattern Detection

The hook detects destructive commands:
- At the start of a command
- After shell operators (`&&`, `||`, `;`, `|`, `$(`, `` ` ``)
- After `sudo` or `xargs`

Safe patterns like `git rm` are explicitly allowed.
