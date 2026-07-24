# Gatehouse × Claude Code

Routes Claude Code tool calls through the gatehouse broker via a PreToolUse
hook. Bash commands and file edits are classified by your gatehouse policy;
`allow` tiers pass silently, `deny` tiers are blocked, and `ask` /
`ask-strong` tiers hold the tool call until you approve — with your passkey
for `ask-strong`.

## Install

```sh
# from the repo root, inside the project you want gated:
adapters/claude-code/install.sh            # writes .claude/settings.json
```

Requires `gate` on PATH (`cargo install --path crates/gate`) and a running
`gatehoused`.

## What it does

- `Bash` commands that are plain argv (`git push origin main`) are matched
  against your policy rules exactly like `gate run` submissions.
- Commands with shell syntax (pipes, `$()`, `&&`, redirects) are submitted
  as opaque `sh -c`, which policy treats as **ask-strong** by default.
- `Write`/`Edit`/`MultiEdit`/`NotebookEdit` become `file_write` requests, so
  writes inside your configured `workspace` prefixes auto-allow and writes
  outside it prompt.
- If the daemon is unreachable the hook returns "ask", deferring to Claude
  Code's own permission prompt instead of blocking the session.

## Honesty section: this is advisory mode

The hook decides; **Claude Code still executes**. That means:

- The binding is at tool-call granularity. Between approval and execution
  the filesystem can change (TOCTOU); the broker is not the executor here.
- Anything that bypasses the harness's hook mechanism bypasses gatehouse.

Advisory mode is a big UX upgrade over rubber-stamp prompts, not a security
boundary. For the enforced model, combine it with one of:

1. **Claude Code sandbox mode ON** — the sandbox denies by default and the
   hook governs what gets allowed through;
2. **Containerized agent** whose only route to the host is the mounted
   agent socket, with commands executed via `gate run` (broker-executes).
