# Gatehouse × Codex CLI

Routes Codex lifecycle `PreToolUse` hooks through gatehouse. Codex is closed
source — this adapter cannot land as an upstream PR; install it in your
`~/.codex` or project `.codex` layer.

## Install

```sh
# enables [features].hooks and writes hooks.json
adapters/codex/install.sh
# or: adapters/codex/install.sh path/to/.codex
```

Requires `gate` on PATH and a running `gatehoused`.

## Behaviour

- Installer writes the official `{ "hooks": { "PreToolUse": [...] } }` shape
  and matches `Bash`, `apply_patch`, `Edit`, and `Write`.
- After install, trust the hook in Codex with `/hooks` (unsigned hooks are
  skipped until reviewed).
- Stdin JSON is Claude-shaped (`tool_name` / `tool_input`). `apply_patch`
  and Bash both expose `tool_input.command`.
- **Exit code 2** = deny (Codex blocks the tool). Allow and “ask” exit 0 so
  Codex can fall back to its own approval UI when the daemon is down.

## Honesty: advisory mode

Codex still executes after an allow. Combine with Codex sandbox /
permission profiles. Prefer `gate run` inside a container when you need
broker-executes.
