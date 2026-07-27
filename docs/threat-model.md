# Threat model (v0.1)

## Goals

1. An agent (or malware in the agent’s context) cannot approve its own
   risky operations.
2. A completed approval cannot be replayed onto a second request, and a live
   approval gesture cannot be *redirected* onto a different pending request.
3. Enrolling a new approver requires a fresh operator action at the machine,
   not just possession of an approval URL.
4. Operators can see a durable, tamper-evident log of decisions.

## Trust boundaries

| Component | Trust |
|-----------|--------|
| `gatehoused` (user’s machine) | Trusted for policy, execution, audit, WebAuthn verify |
| `gate` / hooks / `gate-mcp` | Untrusted relative to policy — they only submit |
| Harness (Claude Code, Codex, Cursor, …) | Untrusted; may ignore advisory hooks |
| Phone / localhost approval UI | Trusted only for user-presence gestures |
| Relay (self-hosted or hosted) | Transport — cannot forge an approval and cannot redirect one at the API level; **can** serve hostile page JavaScript and **does** see every pending summary in cleartext (see below) |

## Relay: what is actually guaranteed today

The relay carries pending-request summaries to the phone and WebAuthn
assertions back. What holds and what does not, as implemented:

**No forgery.** A compromised relay cannot manufacture an approval out of
nothing. Releasing a request requires an assertion that verifies against an
enrolled phone passkey (`approve_finish` in `crates/gatehoused/src/phone.rs`);
the daemon — not the relay — verifies it and only then builds the
`ApprovalEnvelope`. Envelopes never cross the relay, so a completed approval
cannot be captured and replayed onto a later request. A finish call carrying
no credential is rejected (covered by the e2e “forged approval” check).

**No redirection at the API level.** The ceremony challenge is derived from
the request instead of being random
(`crates/gatehoused/src/binding.rs`):

```text
challenge = SHA-256( JCS({ digest, nonce, purpose:"gatehouse-approval-v1" }) )
```

`digest` is the SHA-256 of the JCS-canonical request; `nonce` is the 256-bit
CSPRNG value the daemon minted for that pending entry. The daemon substitutes
this challenge into both the options sent to the browser and the webauthn-rs
ceremony state, so the authenticator signs it as part of `clientDataJSON`.
At `approve_finish` the daemon re-derives the challenge **from the pending
request it is about to release** and compares it against the challenge read
back out of the signed `clientDataJSON`, failing closed on mismatch. The
release therefore no longer rests on the daemon-local `auth_states` pairing:
a relay that starts a ceremony for digest B and then asks for digest A to be
released produces an assertion that does not verify against A. All signature,
origin and RP verification stays inside webauthn-rs; only the challenge value
is supplied by Gatehouse.

**Still does not hold: the relay serves the page.** A relay that ships
malicious PWA JavaScript controls what the human reads. It can show request
A’s summary while calling `/api/approve/start` for request B and suppress the
on-screen code — the ceremony is self-consistently bound to B, but the
human’s consent was obtained under a false description. Two things bound
this:

- `approve/start` returns a **verification code** — the first 8 hex of the
  digest the daemon actually bound the ceremony to — and the approval page
  displays it next to the approve button. The daemon’s terminal prints the
  same 8 characters in its `APPROVAL NEEDED [xxxxxxxx]` line. The human
  comparing the two has an out-of-band check the relay cannot influence,
  because the daemon computes the code from its own pending state. Hostile
  page JavaScript can suppress or fake the on-screen code; it cannot change
  what the terminal prints.
- Every release is recorded in the audit log with its summary.

The full fix is a client the relay does not get to author — a native or
pinned app rendering the summary itself. That is a later phase; until then,
**self-host the relay** and use the code comparison when the request matters.

## Hosted mode: what tenant isolation does and does not buy

One relay can carry several brokers (`gatehoused device-enroll`). Each enrolled
device gets two CSPRNG secrets of its own: a control-plane `token` for its
WebSocket and a `phone_token` for its phone. Nothing is shared. On every phone
API route the relay derives the target device *from the presented
`phone_token`* — a constant-time scan of `devices.json` — and treats `?d=` /
`X-Gatehouse-Device` only as a cross-check that must agree. Tenant A's phone
therefore cannot read tenant B's pending summaries, deny B's requests, or aim
a passkey enrollment at B's daemon; it gets 403. The relay-wide `phone_token`
in relay `config.json` authorizes the legacy single-tenant mTLS link and
nothing else. The mTLS listener is likewise single-tenant by construction: a
client cert proves possession of the shared CA-signed key, not of a device
token, so that channel's identity is fixed and its `Hello` cannot claim
another device.

**This isolates tenants from each other, not from the relay operator.**
Pending-request summaries — the command line, the file path, the host —
cross the relay as cleartext JSON RPC, so whoever runs the relay reads every
tenant's summaries and sees the timing of every approval. `devices.json` holds
every tenant's bearer secrets in cleartext on the relay host (0600), so relay
host compromise is total for routing: the attacker can impersonate any phone
and any broker's control plane. What that still does not buy is an approval —
releasing a request needs a WebAuthn assertion the *daemon* verifies against an
enrolled passkey, bound to the request digest, and enrolling a new passkey
needs a one-time code off the operator's own terminal. A hostile relay's
leverage remains what it is for the single-tenant case: deceiving the human
through the page it serves.

If summaries are sensitive, self-host the relay.

## Enrollment

Enrolling a passkey mints a new approver, so it is not gated by the approval
URL alone. `register_start` on both channels (`web.rs` `/api/register/start`
and `phone.rs::register_start`) requires a one-time code from
`gate enroll-code`, printed on the operator’s terminal: 8 characters from a
CSPRNG, single-use, 5-minute TTL, compared in constant time
(`crates/gatehoused/src/enroll.rs`). Someone who obtains the phone URL and its
bearer token still cannot enroll their own authenticator without simultaneous
access to the operator’s terminal.

## What hook / MCP “advisory” mode does NOT protect against

- Harness with hooks disabled, bypassed, or not installed
- Direct execution outside `gate run` / `gated_exec` when the sandbox is off
- TOCTOU between allow and harness-side execution (hook mode)
- A compromised `gatehoused` process or the operator’s OS user account
- Social engineering that tricks the human into approving a summary they did
  not read. The signature covers the request *identity* (digest + nonce), so
  the release cannot be steered onto a different request — but nothing forces
  the human to read the summary the daemon shows for it.

## Enforced deployment pattern

1. Agent runs in a sandbox/container with **no** ambient network/exec.
2. Only path to side effects is the gatehouse agent socket (`gate run` /
   `gated_exec`).
3. Dangerous tiers require passkey / phone assertion verified by the daemon.

## Audit

`~/.local/share/gatehouse/audit.jsonl` (or `$GATEHOUSE_DATA_DIR`) is an
append-only hash chain. Verify with `gate audit verify`.
