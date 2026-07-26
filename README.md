# Gatehouse

A harness-agnostic approval broker for AI coding agents.

Sandboxed agents route risky operations through a privileged host daemon (`gatehoused`).
Safe operations pass by policy; dangerous ones require a cryptographically request-bound
approval signed by a human-presence gesture — Touch ID on macOS, a phone passkey via
WebAuthn later. The agent cannot approve its own requests, and an approval for one
request cannot be replayed or swapped onto another.

## Status

Early development. See [docs/PLAN.md](docs/PLAN.md) for the phased roadmap.

- [x] Phase 1 — core daemon, wire protocol, policy engine, terminal approvals
- [x] Phase 2 — passkey (WebAuthn) approval (localhost Touch ID / platform authenticator)
- [x] Phase 3 — Claude Code adapter (PreToolUse hook)
- [x] Phase 4 — phone approval (WebAuthn PWA + self-hosted mTLS relay)
- [x] Phase 5 — MCP gateway, `gate audit verify` / `policy test`, threat model
- [ ] Phase 6 — hosted / integrator relay (stable phone RP without Tailscale)
- [ ] Phase 7 — more harness adapters (Cursor, Codex, OpenCode, Pi, …)
- [ ] Phase 8 — Windows + Linux support for `gatehoused` / `gate`
- [ ] Phase 9 — dedicated approval app (research; passkeys + push, not OTP)

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

## Install

```sh
cargo install --path crates/gatehoused
cargo install --path crates/gate
# ensure ~/.cargo/bin is on PATH
```

## Approval channels (pick one)

Passkeys are bound to a **relying-party ID** (hostname). Mac Touch ID and phone
Face ID are therefore separate enrollments — you choose how far you want the
approval UI to reach.

### 1. Mac only (default — no phone, no Tailscale)

Best for day-to-day use at the machine. The daemon serves a localhost approval
page; `gate enroll` registers a platform passkey (Touch ID on Apple silicon).

```sh
gatehoused --no-open          # terminal 1
gate enroll                   # prints a one-time code and opens the page
gate run -- git push          # ask-strong → Touch ID on this Mac
```

No extra networking. Push notifications and phones are not involved.

### Enrolling a passkey (both channels)

Enrollment mints a new approver, so the approval URL alone is not enough:
`register/start` requires a **one-time enrollment code**. `gate enroll` prints
one and opens the page; `gate enroll-code` prints one on demand (e.g. when the
page is already open on a phone).

```sh
gate enroll-code
# enrollment code: K7QW3MTZ  (valid 300s, single use)
```

Type it into the prompt on the approval page, then complete the authenticator
gesture. Codes are CSPRNG-generated, single-use and expire after 5 minutes;
anyone who has the phone URL but not your terminal cannot enroll.

### Verification code on approval

When you approve, the page shows a **verification code** — the same 8
characters the daemon prints in its `APPROVAL NEEDED [xxxxxxxx]` line. The
WebAuthn challenge is derived from the request itself, so the daemon refuses
to release anything the assertion was not bound to; the code is the
out-of-band check that the request on screen is the one your terminal is
waiting on. Confirm they match before you touch the sensor.

### 2. Phone via self-hosted relay

Use when you want Face ID / fingerprint away from the desk. The phone must open
an **HTTPS origin whose hostname is the WebAuthn RP ID**. That reachability is
your choice — Gatehouse does not require a vendor cloud:

| How the phone reaches the relay | Notes |
|---------------------------------|--------|
| **Tailscale** (MagicDNS / Serve / Funnel) | Easiest for personal setups; no public internet exposure required for Serve |
| **Your own VPS** running `gatehoused relay` | Copy `~/.local/share/gatehouse/relay/` (or `$GATEHOUSE_DATA_DIR/relay/`) to that host |
| **LAN hostname + trusted cert** | Possible but painful (phones dislike self-signed / `.local`) |

```sh
# guided setup (TTY): detects Tailscale and asks Y/n/custom
gatehoused relay-init

# or non-interactive Tailscale:
gatehoused relay-init --tailscale

# change hostname later (re-enroll phone passkeys if rp_id changes):
gatehoused relay-init --tailscale --force
# keep the same ?t= token in bookmarks:
gatehoused relay-init --tailscale --force --keep-token

gatehoused relay-show          # print current phone URL
gatehoused relay               # terminal 1
gatehoused --relay-url https://<your-host>:8788 --no-open   # terminal 2
```

Open the printed phone URL **in the phone’s browser**, run `gate enroll-code`
on the machine and type the code into the page to enroll, then
`gate run -- git push`.

Details: [docs/relay.md](docs/relay.md). Future integrator-hosted endpoints
(no Tailscale for end users): [docs/hosted-relay.md](docs/hosted-relay.md).

### 3. Claude Code hook (advisory)

Routes harness tool calls through the broker. This is UX, not the security
boundary — combine with sandbox / `gate run` for enforcement.
See [adapters/claude-code/README.md](adapters/claude-code/README.md).

## Why “scan QR on phone” fails for localhost enroll

Browsers often offer a QR code so a *phone* can act as a roaming authenticator
for a ceremony that started on the Mac. That hybrid flow still binds the
passkey to the **page’s RP ID** — for the default Mac UI that is `localhost`.

Phones generally **cannot** create a usable passkey for `localhost` (and
self-signed `https://localhost` is worse). The rejection you saw is expected,
not a Gatehouse bug.

| Goal | Do this |
|------|---------|
| Approve on this Mac | `gate enroll` on the localhost page; use Touch ID (no QR) |
| Approve on the phone | Run the relay with a real hostname; open that URL *on the phone* and enroll there |

APNs / ntfy can only *notify* you that something is pending. They are not the
approval channel — the passkey assertion over HTTPS is.

## CLI polish

```sh
gate policy test -- git push origin main   # dry-run tier resolution
gate audit verify                          # hash-chain check
```

MCP: [adapters/mcp-gateway/README.md](adapters/mcp-gateway/README.md)  
Threat model: [docs/threat-model.md](docs/threat-model.md)  
Container recipe: [docker-compose.yml](docker-compose.yml)

## Layout

- `crates/gatehouse-proto` — canonical request format, digests, signature envelopes, wire protocol
- `crates/gatehoused` — host daemon: policy engine, approval channels, executor, audit log, phone relay
- `crates/gate` — client CLI: `gate run -- <cmd>`, `gate ask`, `gate grant`, `gate hook`
- `adapters/claude-code` — PreToolUse hook integration
- [docs/relay.md](docs/relay.md) — phone PWA + mTLS relay setup
- [docs/hosted-relay.md](docs/hosted-relay.md) — Phase 6 integrator / hosted relay sketch
