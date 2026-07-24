# Gatehouse × Cursor

Cursor’s agent is closed source — there is **no upstream PR path** for a
first-class Gatehouse integration. Options today:

1. **MCP (Phase 5):** when Gatehouse exposes `gated_exec` / `gated_fetch`, add
   them as an MCP server in Cursor settings and prefer those tools in rules.
2. **Shell discipline:** project rules that tell the agent to run risky
   commands via `gate run -- …` (honor-system; not a security boundary).
3. **Container / VM:** run the Cursor agent environment with no egress except
   the gatehouse agent socket (broker-executes).

Do not expect a PreToolUse-style hook until Cursor ships one. This directory
exists so the limitation is documented next to the working adapters.
