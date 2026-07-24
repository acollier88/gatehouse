# Gatehouse MCP gateway

Exposes Gatehouse to any MCP-capable harness via `gate-mcp` (stdio JSON-RPC).

## Tools

| Tool | Behaviour |
|------|-----------|
| `gated_exec` | Submits an exec request; on allow the **daemon executes** and streams output |
| `gated_fetch` | Submits a `net` request for policy; on allow this process HTTP GETs the URL |

## Install (Cursor / Claude Desktop style)

```json
{
  "mcpServers": {
    "gatehouse": {
      "command": "gate-mcp",
      "args": []
    }
  }
}
```

Build/install: `cargo install --path crates/gate-mcp` (requires running `gatehoused`).

## Honesty

- `gated_exec` uses the broker-executes path (stronger).
- `gated_fetch` is broker-permits then local GET (TOCTOU possible between allow and fetch).
- Prefer these tools over raw shell when the harness cannot install PreToolUse hooks.
