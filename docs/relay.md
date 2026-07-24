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
# RP ID = hostname phones will see (Tailscale MagicDNS, Funnel hostname, etc.)
gatehoused relay-init \
  --rp-id box.tailnet.ts.net \
  --origin https://box.tailnet.ts.net:8787

# Material lands in $GATEHOUSE_DATA_DIR/relay/ (certs + config.json, mode 0600).
# The init log prints the phone URL with the bearer token.
```

Copy the same `relay/` directory to whichever machine runs the relay if it is
not the daemon host. The daemon needs the client cert; the relay needs the
server cert + CA.

## Run

```sh
# On the host you expose (or the same machine, behind Tailscale Funnel):
gatehoused relay --listen 0.0.0.0:8787 --daemon-listen 0.0.0.0:8788

# On the machine running agents (dial-out; NAT-friendly):
gatehoused --relay-url https://box.tailnet.ts.net:8788
```

- **8787** — phone HTTPS (PWA). Auth: `?t=` / `X-Gatehouse-Token`.
- **8788** — daemon mTLS WebSocket at `/ws`. Client certificate required.

Open the phone URL (or `gate enroll` / `gate approvals` once `relay-init` has
run). Enroll a passkey on the phone, then trigger an `ask-strong` op
(`gate run -- git push`).

## Threat notes

| Event | Result |
|-------|--------|
| Relay killed mid-approval | Daemon times out → deny |
| Relay sends `{approved:true}` without assertion | HTTP 401; pending untouched |
| Relay swaps digests | Daemon ceremony map + envelope binding reject mismatch |
| Token leaked | Attacker can see pending summaries / start ceremonies; still cannot mint a valid authenticator assertion |

Localhost Touch ID enrollments (`passkeys.json`) and phone enrollments
(`passkeys-phone.json`) are separate — WebAuthn credentials are RP-bound.
