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

Hosted / device-token mode (no shared CA copy):

```sh
gatehoused relay-init --hosted --rp-id approve.example.com \
  --origin https://approve.example.com:8787 --yes
gatehoused device-enroll --label laptop --write \
  --endpoint https://approve.example.com:8787
```

Each `device-enroll` mints that device its **own** phone bearer alongside its
control-plane token, and prints a phone URL carrying it
(`/?t=<device phone_token>&d=<device_id>`). The relay-wide `phone_token` in
`config.json` stays with the single-tenant mTLS path only. See
[hosted-relay.md](hosted-relay.md).

## Run

```sh
# On the host you expose (or the same machine, behind Tailscale Funnel):
gatehoused relay --listen 0.0.0.0:8787 --daemon-listen 0.0.0.0:8788

# On the machine running agents (dial-out; NAT-friendly):
gatehoused --relay-url https://box.tailnet.ts.net:8788
```

- **8787** — phone HTTPS (PWA). Auth: `?t=` / `X-Gatehouse-Token`. In hosted
  mode this port also carries the daemon WebSocket at `/ws`, authenticated
  with `Authorization: Bearer <device token>`.
- **8788** — daemon mTLS WebSocket at `/ws`. Client certificate required.
  Single-tenant: this channel is always the `_mtls` identity regardless of
  what its `Hello` claims.

Open the phone URL **on the phone** (Safari/Chrome). Tap "Enroll a passkey";
the page asks for a one-time enrollment code, which you get by running
`gate enroll-code` on the machine running `gatehoused` (8 characters, single
use, valid 5 minutes). Then trigger an `ask-strong` op
(`gate run -- git push`).

When approving, the card shows a **verification code** — the first 8 hex of
the request digest, the same value the daemon prints as
`APPROVAL NEEDED [xxxxxxxx]`. Check they match before you use the sensor.

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
| Relay swaps digests | Challenge is derived from `{digest, nonce}`; the daemon re-derives it from the request it is releasing and rejects a mismatch |
| Relay serves hostile page JS | Not prevented — it can misdescribe the request. The verification code shown by the daemon vs. the terminal is the human's check; a pinned client is the real fix |
| Token leaked | Attacker can see pending summaries / start ceremonies; still cannot mint a valid authenticator assertion, and cannot enroll one without a `gate enroll-code` code |
| One tenant's phone token leaked (hosted) | Blast radius is that one device. The token *is* the device selector, so it cannot address another tenant's broker (403), and it cannot fall through to whichever broker happens to be connected |

Localhost Touch ID enrollments (`passkeys.json`) and phone enrollments
(`passkeys-phone.json`) are separate — WebAuthn credentials are RP-bound.
