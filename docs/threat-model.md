# Threat model (v0.1)

## Goals

1. An agent (or malware in the agent’s context) cannot approve its own
   risky operations.
2. A completed approval cannot be replayed onto a second request. (Not yet:
   a live approval gesture cannot be *redirected* onto a different pending
   request — see “Relay” below.)
3. Operators can see a durable, tamper-evident log of decisions.

## Trust boundaries

| Component | Trust |
|-----------|--------|
| `gatehoused` (user’s machine) | Trusted for policy, execution, audit, WebAuthn verify |
| `gate` / hooks / `gate-mcp` | Untrusted relative to policy — they only submit |
| Harness (Claude Code, Codex, Cursor, …) | Untrusted; may ignore advisory hooks |
| Phone / localhost approval UI | Trusted only for user-presence gestures |
| Relay (self-hosted or hosted) | Transport — cannot forge an approval, **can** redirect a real one (see below) |

## Relay: what is actually guaranteed today

The relay carries pending-request summaries to the phone and WebAuthn
assertions back. What holds and what does not, as implemented:

**Holds.** A compromised relay cannot manufacture an approval out of nothing.
Releasing a request requires an assertion that verifies against an enrolled
phone passkey (`approve_finish` in `crates/gatehoused/src/phone.rs`); the
daemon — not the relay — verifies it and only then builds the
`ApprovalEnvelope`. Envelopes never cross the relay, so a completed approval
cannot be captured and replayed onto a later request. A finish call carrying
no credential is rejected (covered by the e2e “forged approval” check).

**Does not hold.** The assertion is *not* bound to the request. The daemon
calls `start_passkey_authentication`, which mints a random challenge with no
digest in it, and remembers the digest↔ceremony pairing only in the
daemon-local `auth_states` map — keyed by a ceremony id the relay supplies.
So a compromised relay can display request A’s summary on the phone while
sending digest B to `/api/approve/start`. The user’s gesture is genuine, the
assertion verifies, and request B is released. In other words: **the relay
cannot invent approvals, but it can choose which pending request the user’s
real approval lands on.**

The blast radius is bounded by there being a genuine user gesture per
release — a hostile relay gets at most one arbitrary pending request approved
per approval the user actually performs, and every release is recorded in the
audit log with its summary.

*Planned fix (next work package):* bind the ceremony to the digest
cryptographically — derive the WebAuthn challenge from the request digest (or
carry the digest in `clientDataJSON` extension data) and have the daemon
re-derive and compare it in `approve_finish`, so a substituted digest fails
verification instead of being trusted from daemon memory. Until that lands,
treat the relay as **partially trusted**: self-host it, or accept that a relay
operator can steer approvals.

## What hook / MCP “advisory” mode does NOT protect against

- Harness with hooks disabled, bypassed, or not installed
- Direct execution outside `gate run` / `gated_exec` when the sandbox is off
- TOCTOU between allow and harness-side execution (hook mode)
- A compromised `gatehoused` process or the operator’s OS user account
- Social engineering that tricks the human into approving the wrong summary.
  The UI shows the summary the daemon holds for that digest, but the
  signature does not yet cover it — see “Relay” above. Today this is UX and
  audit review, not cryptography.

## Enforced deployment pattern

1. Agent runs in a sandbox/container with **no** ambient network/exec.
2. Only path to side effects is the gatehouse agent socket (`gate run` /
   `gated_exec`).
3. Dangerous tiers require passkey / phone assertion verified by the daemon.

## Audit

`~/.local/share/gatehouse/audit.jsonl` (or `$GATEHOUSE_DATA_DIR`) is an
append-only hash chain. Verify with `gate audit verify`.
