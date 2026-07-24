# Threat model (v0.1)

## Goals

1. An agent (or malware in the agent’s context) cannot approve its own
   risky operations.
2. An approval for request A cannot be replayed onto request B.
3. Operators can see a durable, tamper-evident log of decisions.

## Trust boundaries

| Component | Trust |
|-----------|--------|
| `gatehoused` (user’s machine) | Trusted for policy, execution, audit, WebAuthn verify |
| `gate` / hooks / `gate-mcp` | Untrusted relative to policy — they only submit |
| Harness (Claude Code, Codex, Cursor, …) | Untrusted; may ignore advisory hooks |
| Phone / localhost approval UI | Trusted only for user-presence gestures |
| Relay (self-hosted or hosted) | **Transport only** — must not be able to forge approvals |

## What hook / MCP “advisory” mode does NOT protect against

- Harness with hooks disabled, bypassed, or not installed
- Direct execution outside `gate run` / `gated_exec` when the sandbox is off
- TOCTOU between allow and harness-side execution (hook mode)
- A compromised `gatehoused` process or the operator’s OS user account
- Social engineering that tricks the human into approving the wrong summary
  (mitigated by binding the signature to the digest, not by UX alone)

## Enforced deployment pattern

1. Agent runs in a sandbox/container with **no** ambient network/exec.
2. Only path to side effects is the gatehouse agent socket (`gate run` /
   `gated_exec`).
3. Dangerous tiers require passkey / phone assertion verified by the daemon.

## Audit

`~/.local/share/gatehouse/audit.jsonl` (or `$GATEHOUSE_DATA_DIR`) is an
append-only hash chain. Verify with `gate audit verify`.
