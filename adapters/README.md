# Gatehouse harness adapters

Out-of-tree integrations that route agent tool calls through `gate hook …`
(**advisory mode**). The harness still executes after an allow — pair with a
sandbox or `gate run` for enforcement.

| Adapter | Path | Upstream PR? | Status |
|---------|------|--------------|--------|
| Claude Code | [claude-code/](claude-code/) | N/A (settings hook) | Shipped |
| Codex CLI | [codex/](codex/) | Closed tool — adapter only | Shipped |
| OpenCode | [opencode/](opencode/) | OSS — prefer upstream later | Plugin shipped |
| Cursor | [cursor/](cursor/) | Closed — no PR path | Docs only |
| Generic / MCP | `gate hook generic` + Phase 5 MCP | Portable | Hook shipped |

Shared CLI:

```sh
gate hook claude-code   # Claude PreToolUse JSON out
gate hook codex         # exit 2 = deny (Codex lifecycle hooks)
gate hook generic       # {"decision","reason"} JSON; exit 2 = deny
```
