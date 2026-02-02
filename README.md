# OpenCode Block Destructive Commands

An OpenCode hook that blocks destructive file deletion commands and directs users to use `trash` instead. This ensures deleted files can be recovered from the system trash.

> **Note:** This is a best-effort attempt to catch common destructive patterns, not a comprehensive security barrier. There will always be edge cases and creative ways to delete files that aren't covered. Use this as one layer of defense, not the only one.

## Blocked Patterns

**Direct commands:**
- `rm`, `shred`, `unlink`, `wipe`, `srm`
- `dd` with `of=` (output file)

**Path variants:**
- `/bin/rm`, `/usr/bin/rm`, `./rm`

**Bypass attempts:**
- `command rm`, `env rm`, `\rm`
- `sudo rm`, `xargs rm`
- Variable expansion: `CMD=rm; $CMD file`

**Subshell execution:**
- `sh -c "rm ..."`, `bash -c "rm ..."`, `zsh -c "rm ..."` (recursive up to 5 levels)

**Find commands:**
- `find . -delete`
- `find . -exec rm {} \;`

## Allowed Commands

- `git rm` (tracked by git, recoverable)
- `echo 'rm test'` (quoted strings are safe)
- All other commands

## Configuration

You can customize the blocked and allowed commands using environment variables:

- `OPENCODE_BLOCK_COMMANDS`: Comma-separated list of additional commands to block.
- `OPENCODE_ALLOW_COMMANDS`: Comma-separated list of commands to explicitly allow (even if they are in the default blocked list).

Example in `.opencode/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bun run /path/to/opencode-rm-rf/src/index.ts",
            "env": {
              "OPENCODE_BLOCK_COMMANDS": "custom-delete",
              "OPENCODE_ALLOW_COMMANDS": "rm"
            }
          }
        ]
      }
    ]
  }
}
```

Replace `/path/to/opencode-rm-rf` with the actual path, or use `$OPENCODE_PROJECT_DIR` if installing per-project.

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
cd opencode-rm-rf
bun install
```

### 4. Configure OpenCode

(See Configuration section above)

## Development

```bash
# Run tests (44 test cases)
bun test

# Build standalone executable (optional, ~60MB)
bun run build
```

## How It Works

The hook runs on every `Bash` tool call via the `PreToolUse` event:

1. Parses JSON input from OpenCode (stdin)
2. Uses `shell-quote` to parse the command into tokens, accurately identifying command positions.
3. Recursively checks subshells (`sh -c`, etc.) up to 5 levels deep.
4. Tracks variable assignments (e.g., `CMD=rm; $CMD file`) to prevent bypasses.
5. Checks for destructive patterns in command positions.
6. Returns exit code 2 with a helpful suggestion if blocked.
7. Returns exit code 0 to allow the command.
