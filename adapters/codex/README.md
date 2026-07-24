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

- Stdin JSON is treated like Claude-shaped hooks (`tool_name` / `tool_input`).
- Shell / bash tools become policy `exec` requests; write/edit tools become
  `file_write`.
- **Exit code 2** = deny (Codex blocks the tool). Allow and “ask” exit 0 so
  Codex can fall back to its own approval UI when the daemon is down.

## Honesty: advisory mode

Codex still executes after an allow. Combine with Codex sandbox /
permission profiles. Prefer `gate run` inside a container when you need
broker-executes.
