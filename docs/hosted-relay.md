# Hosted / integrator relay (Phase 6)

Self-hosted + Tailscale cover individuals. Integrators and teams can publish a
**named approval endpoint** without every user running Tailscale. The relay
remains transport-only: ceremonies and passkey verification stay on the user’s
`gatehoused`.

## Non-negotiables (same as Phase 4)

1. The relay is **transport only**. WebAuthn ceremonies are started and
   finished by the user’s broker. Relay compromise ≠ forged approval.
2. Passkeys bind to an **RP ID** the phone actually loads in a browser/WebView.
3. Push (APNs, FCM, ntfy) is optional wake-up only — never the approval secret.

## Deployment modes

```
  gatehoused (user) --mTLS or device token-->  relay endpoint
                                                 |  integrator hosted
  phone PWA/WebView <--HTTPS+passkey-->          |  customer self-hosted
                                                 |  personal Tailscale/VPS
```

| Mode | Who runs the relay | Daemon auth | When to use |
|------|--------------------|-------------|-------------|
| **Personal Tailscale / VPS** | User | mTLS (default) | Power users (Phase 4) |
| **Integrator-hosted** | Cursor / Anthropic / … | Device enrollment token | Zero Tailscale for end users |
| **Customer-hosted** | Enterprise IT | Token or mTLS | Data-residency / private network |
| **BYO URL** | Any compatible relay | Token via `device.json` / `relay.toml` | Escape hatch |

## Token / hosted setup (this repo)

On the **relay host**:

```bash
gatehoused relay-init --hosted \
  --rp-id approve.example.com \
  --origin https://approve.example.com:8787 \
  --force --yes

gatehoused relay --listen 0.0.0.0:8787 --daemon-listen 0.0.0.0:8788

# Enroll each broker machine (writes devices.json on the relay host)
gatehoused device-enroll --label laptop \
  --endpoint https://approve.example.com:8787 --write
# → device.json (copy to the laptop) + that device's own phone URL
```

Each enrollment mints **two** CSPRNG secrets scoped to that device alone:

| Secret | Presented as | Purpose |
|--------|--------------|---------|
| `token` | `Authorization: Bearer` on the daemon `/ws` | Authenticates that broker's control-plane socket |
| `phone_token` | `X-Gatehouse-Token` / `?t=` | Authenticates that device's phone |

Nothing is shared between devices. The relay-wide `phone_token` in relay
`config.json` is *not* a tenant credential: it authorizes only the legacy
single-tenant mTLS link, and presenting it against an enrolled `device_id`
is rejected with 403.

On the **broker machine** (after copying `device.json` into the data dir, or
writing `~/.config/gatehouse/relay.toml`):

```toml
# ~/.config/gatehouse/relay.toml
endpoint = "https://approve.example.com:8787"
```

```bash
# device.json already present → dials with Bearer token to /ws on the phone port
gatehoused --no-open

# Or one-shot without a file:
gatehoused --relay-url https://approve.example.com:8787 \
  --relay-token <token> --no-open
```

Phone opens `https://approve.example.com:8787/?t=<device phone_token>&d=<device_id>`
— the URL `device-enroll` prints, carrying that device's own bearer.

**The token selects the device; `d=` only cross-checks it.** The relay derives
the target broker from the presented `phone_token` (constant-time scan of
`devices.json`) and then requires any `d=` query or `X-Gatehouse-Device` header
to name that same device. So:

- Device A's phone token addressing device B → **403**, on every route.
- Device A's phone token with no `d=` at all → still device A, never a
  fallback to "whichever broker happens to be connected".
- An unknown token → **401**.

A tenant therefore cannot read another tenant's pending summaries, deny their
requests, or aim a passkey enrollment at their daemon.

`daemon_auth` in relay `config.json`:

| Value | Behavior |
|-------|----------|
| `mtls` (default) | Separate mTLS daemon port (Phase 4) |
| `token` | Bearer WS on phone port `/ws` only (`--hosted`) |
| `both` | Accept either |

The mTLS listener is single-tenant by construction. A client cert proves
possession of the shared CA-signed key, not of any device token, so an mTLS
connection is always the `_mtls` identity — its `Hello` cannot claim an
enrolled `device_id`. Multi-device routing requires the token listener.

## Multi-tenant responsibilities

| Party | Holds | Must not |
|-------|-------|----------|
| Integrator relay | Routing, push fan-out, TLS for the phone origin, `devices.json` | Private keys for user passkeys; ability to mint valid assertions |
| User broker (`gatehoused`) | Passkeys, policy, audit log, ceremony verify | Blindly trust relay “approved” flags |
| Phone | Platform authenticator | Treat push payload as authorization |

`devices.json` holds every tenant's bearer secrets in cleartext (0600), and
pending-request summaries pass through the relay as cleartext RPC. Per-device
tokens isolate tenants **from each other**, not from the relay operator — see
the hosted-mode section of [threat-model.md](threat-model.md).

Changing RP ID (Tailscale → hosted, or between hosts) always means **re-enroll**
phone passkeys. `relay-init --force` already warns.

## What integrators implement

Minimum viable hosted relay (compatible with this binary’s token mode):

- Terminate HTTPS for a stable hostname (RP ID).
- Authenticate daemons with enrollment tokens (`Authorization: Bearer`).
- Map `device_id →` live control-plane connection.
- Route the phone API by **deriving the device from the phone bearer**, not
  from `d=`. Treat `d=` as a cross-check that must agree, and compare tokens
  in constant time.
- Proxy the Phase 4 RPC methods (`pending`, register/*, approve/*, deny)
  unmodified — the daemon enforces enrollment codes and challenge binding on
  the far side, and a relay that rewrites bodies only breaks itself.
- Serve the approval PWA (or embed in a native shell).
- Optional: Web Push / APNs — still not an approval.

Out of scope for the relay: policy evaluation, audit hash-chain, executing
commands. Those stay on the broker.

## Relation to Phase 5

Phase 5 (MCP gateway, harness recipes, threat-model polish) is **agent surface
area**. Phase 6 is **approval reachability for phones at integrator scale**.
Neither blocks Mac-local Touch ID.
