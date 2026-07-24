# Phone approval relay

Phase 4 adds a self-hosted relay so a phone (Face ID / fingerprint passkey)
can approve `ask-strong` requests. The relay is **transport only**: WebAuthn
ceremonies and verification always run on `gatehoused`. A compromised relay
cannot forge an approval without a valid assertion.

ntfy.sh is not on the approval path. Pending delivery to the PWA is via
authenticated polling (plus an optional service-worker notification). You may
separately ping yourself with ntfy for awareness; that ping is not proof of
approval.

## Bootstrap

```sh
# Interactive: detects Tailscale MagicDNS and asks whether to use it
gatehoused relay-init

# Non-interactive Tailscale
gatehoused relay-init --tailscale --yes

# Explicit custom / future hosted RP
gatehoused relay-init --rp-id approve.example.com --origin https://approve.example.com

# Re-setup later (updates cert SANs + URLs). Prefer --keep-token if you
# already bookmarked the phone URL. RP ID change ⇒ re-enroll passkeys.
gatehoused relay-init --tailscale --force --keep-token
gatehoused relay-show
```

Material lands in `$GATEHOUSE_DATA_DIR/relay/` (certs + `config.json`, mode
0600), including `transport` (`tailscale` | `custom` | …).

Copy the same `relay/` directory to whichever machine runs the relay if it is
not the daemon host. The daemon needs the client cert; the relay needs the
server cert + CA.

Integrator-hosted endpoints (Cursor/Claude/etc. providing the phone RP):
see [hosted-relay.md](hosted-relay.md).

## Run

```sh
# On the host you expose (or the same machine, behind Tailscale Funnel):
gatehoused relay --listen 0.0.0.0:8787 --daemon-listen 0.0.0.0:8788

# On the machine running agents (dial-out; NAT-friendly):
gatehoused --relay-url https://box.tailnet.ts.net:8788
```

- **8787** — phone HTTPS (PWA). Auth: `?t=` / `X-Gatehouse-Token`.
- **8788** — daemon mTLS WebSocket at `/ws`. Client certificate required.

Open the phone URL **on the phone** (Safari/Chrome). Enroll a passkey there,
then trigger an `ask-strong` op (`gate run -- git push`).

`gate enroll` prefers the relay URL once `relay-init` has run; on a phone that
is correct. On the Mac localhost page, prefer Touch ID — do **not** use the
browser’s “save passkey on phone via QR” offer for `localhost` RP (platforms
reject it). See the README “Why scan QR fails” section.

Push (APNs, ntfy, etc.) is optional awareness only. Pending requests are
polled by the PWA; the approval itself is always a WebAuthn assertion verified
by the daemon.

## Threat notes

| Event | Result |
|-------|--------|
| Relay killed mid-approval | Daemon times out → deny |
| Relay sends `{approved:true}` without assertion | HTTP 401; pending untouched |
| Relay swaps digests | Daemon ceremony map + envelope binding reject mismatch |
| Token leaked | Attacker can see pending summaries / start ceremonies; still cannot mint a valid authenticator assertion |

Localhost Touch ID enrollments (`passkeys.json`) and phone enrollments
(`passkeys-phone.json`) are separate — WebAuthn credentials are RP-bound.
