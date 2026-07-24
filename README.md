# Gatehouse

A harness-agnostic approval broker for AI coding agents.

Sandboxed agents route risky operations through a privileged host daemon (`gatehoused`).
Safe operations pass by policy; dangerous ones require a cryptographically request-bound
approval signed by a human-presence gesture — Touch ID on macOS, a phone passkey via
WebAuthn later. The agent cannot approve its own requests, and an approval for one
request cannot be replayed or swapped onto another.

## Status

Early development. See [docs/PLAN.md](docs/PLAN.md) for the phased roadmap.

- [ ] Phase 1 — core daemon, wire protocol, policy engine, terminal approvals
- [ ] Phase 2 — passkey (WebAuthn) approval + Touch ID / Secure Enclave signer
- [ ] Phase 3 — Claude Code adapter (PreToolUse hook)
- [ ] Phase 4 — phone approval (WebAuthn PWA + self-hosted relay)
- [ ] Phase 5 — MCP gateway adapter, audit tooling, threat-model docs

## Design principles

1. **Enforce at the sandbox boundary, not hooks.** Harness hooks are adapters; the
   security story assumes the sandbox denies everything and the broker socket is the
   only escape hatch.
2. **Approval is bound to the request.** Approvers sign `SHA-256(canonical_request)`
   plus a nonce and expiry with a hardware-backed key. No bare OTPs.
3. **Broker-executes over broker-permits** wherever the integration allows, killing
   time-of-check/time-of-use attacks.
4. **Policy tiers fight approval fatigue.** Biometric prompts are reserved for
   genuinely dangerous operations; workspace-scoped edits auto-pass.

## Layout

- `crates/gatehouse-proto` — canonical request format, digests, signature envelopes, wire protocol
- `crates/gatehoused` — host daemon: policy engine, approval channels, executor, audit log
- `crates/gate` — client CLI: `gate run -- <cmd>`, `gate ask`, `gate grant`
- `adapters/claude-code` — PreToolUse hook integration
