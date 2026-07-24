# Hosted / integrator relay (Phase 6 sketch)

Self-hosted + Tailscale cover individuals. Integrators (Cursor, Claude Code,
Codex, Pi, OpenCode, …) and teams will want a **named approval endpoint**
without every user running Tailscale. This doc defines the shape so Phase 6
can land without re-litigating the trust model.

## Non-negotiables (same as Phase 4)

1. The relay is **transport only**. WebAuthn ceremonies are started and
   finished by the user’s `gatehoused` (or an equivalent broker the user
   controls). Relay compromise ≠ forged approval.
2. Passkeys bind to an **RP ID** the phone actually loads in a browser/WebView.
3. Push (APNs, FCM, ntfy) is optional wake-up only — never the approval secret.

## Deployment modes

```
  gatehoused (user) --mTLS/device auth-->  relay endpoint
                                              |  integrator hosted
  phone PWA/WebView <--HTTPS+passkey-->       |  customer self-hosted
                                              |  personal Tailscale/VPS
```

| Mode | Who runs the relay | RP ID / origin | When to use |
|------|--------------------|----------------|-------------|
| **Personal Tailscale / VPS** | User | User’s hostname | Power users (Phase 4 today) |
| **Integrator-hosted** | Cursor / Anthropic / … | e.g. `approve.cursor.sh` or per-tenant subdomain | Zero Tailscale for end users |
| **Customer-hosted** | Enterprise IT | `gatehouse.corp.example` | Data-residency / private network |
| **BYO URL** | User points daemon at any compatible relay | Whatever that URL’s host is | Escape hatch |

Config sketch (daemon side):

```toml
# ~/.config/gatehouse/relay.toml  (future)
endpoint = "https://approve.example.com"   # or ts / VPS / localhost
# auth: mTLS client cert (personal) OR device enrollment token (hosted)
```

Integrators expose the same phone API surface Phase 4 already uses
(`/api/pending`, register/*, approve/*, deny) plus a daemon control plane
equivalent to today’s mTLS `/ws` RPCs. Wire format can stay JSON; auth for
multi-tenant becomes “enrolled device” rather than a shared CA file.

## Multi-tenant responsibilities

| Party | Holds | Must not |
|-------|-------|----------|
| Integrator relay | Routing, push fan-out, TLS for the phone origin | Private keys for user passkeys; ability to mint valid assertions |
| User broker (`gatehoused`) | Passkeys, policy, audit log, ceremony verify | Blindly trust relay “approved” flags |
| Phone | Platform authenticator | Treat push payload as authorization |

Enrollment for hosted mode (future):

1. User signs in to integrator (or pastes a one-time pair code).
2. Broker receives a device credential; relay maps `device_id → user`.
3. Phone opens `https://approve.integrator.example/?t=…` (or app links).
4. Passkey RP ID = that hostname — **integrator’s domain**, not `localhost`.

Changing RP ID (moving from Tailscale → hosted, or between hosts) always
means **re-enroll** phone passkeys. `relay-init --force` already warns.

## What integrators implement

Minimum viable hosted relay:

- Terminate HTTPS for a stable hostname (RP ID).
- Authenticate daemons (mTLS or enrollment token).
- Proxy the Phase 4 RPC methods to the correct daemon connection.
- Serve the approval PWA (or embed in a native shell).
- Optional: Web Push / APNs for “approval needed” using the existing
  summary text — still not an approval.

Out of scope for the relay: policy evaluation, audit hash-chain, executing
commands. Those stay on the broker.

## Relation to Phase 5

Phase 5 (MCP gateway, harness recipes, threat-model polish) stays focused on
**agent surface area**. Phase 6 is **approval reachability for phones at
integrator scale**. They can ship in either order; neither blocks Mac-local
Touch ID.
