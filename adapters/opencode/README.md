# Gatehouse × OpenCode

OpenCode is OSS and uses a TypeScript plugin system (`tool.execute.before`)
rather than Claude’s `settings.json` hooks. This adapter ships a tiny plugin
that calls `gate hook generic`.

Prefer an upstream PR to OpenCode once the integration stabilizes; until then
drop the plugin into `.opencode/plugins/`.

## Install

```sh
adapters/opencode/install.sh
# copies plugin + patches opencode.json
```

Requires `gate` on PATH and Node-capable OpenCode host. Daemon must be running.

## Honesty: advisory mode

Same ceiling as Claude Code: the plugin can throw to block, but OpenCode is
still the executor. Use sandboxing / `gate run` for enforcement.
