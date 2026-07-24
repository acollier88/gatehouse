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
# → device.json (copy to the laptop) + phone URL with &d=device_id
```

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

Phone opens `https://approve.example.com:8787/?t=<phone_token>&d=<device_id>`.
The `d=` query (or `X-Gatehouse-Device`) pins API calls to that broker so two
enrolled daemons cannot approve each other’s requests.

`daemon_auth` in relay `config.json`:

| Value | Behavior |
|-------|----------|
| `mtls` (default) | Separate mTLS daemon port (Phase 4) |
| `token` | Bearer WS on phone port `/ws` only (`--hosted`) |
| `both` | Accept either |

## Multi-tenant responsibilities

| Party | Holds | Must not |
|-------|-------|----------|
| Integrator relay | Routing, push fan-out, TLS for the phone origin, `devices.json` | Private keys for user passkeys; ability to mint valid assertions |
| User broker (`gatehoused`) | Passkeys, policy, audit log, ceremony verify | Blindly trust relay “approved” flags |
| Phone | Platform authenticator | Treat push payload as authorization |

Changing RP ID (Tailscale → hosted, or between hosts) always means **re-enroll**
phone passkeys. `relay-init --force` already warns.

## What integrators implement

Minimum viable hosted relay (compatible with this binary’s token mode):

- Terminate HTTPS for a stable hostname (RP ID).
- Authenticate daemons with enrollment tokens (`Authorization: Bearer`).
- Map `device_id →` live control-plane connection; route phone API by `d=`.
- Proxy the Phase 4 RPC methods (`pending`, register/*, approve/*, deny).
- Serve the approval PWA (or embed in a native shell).
- Optional: Web Push / APNs — still not an approval.

Out of scope for the relay: policy evaluation, audit hash-chain, executing
commands. Those stay on the broker.

## Relation to Phase 5

Phase 5 (MCP gateway, harness recipes, threat-model polish) is **agent surface
area**. Phase 6 is **approval reachability for phones at integrator scale**.
Neither blocks Mac-local Touch ID.
