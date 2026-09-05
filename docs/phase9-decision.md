# Phase 9 decision — dedicated approval app

**Date:** 2026-08-16  
**Status:** decided (leaves research)

PLAN.md Phase 9 required a written go/no-go before a store app: PWA-only vs
thin native shell vs full app, push provider, and explicit non-goals.

## Decision

**Thin native shell** around the existing phone PWA.

- The iOS AgentBridge Approvals tab loads the current relay origin
  (`/?t=…&d=…`) in a WKWebView. Enrollment, Face ID, verification code, and
  deny stay the Phase 4 WebAuthn ceremony on the daemon. No new crypto.
- Native `AuthenticationServices` + Associated Domains / AASA is **out of v1**.
  `ASWebAuthenticationSession` is not a drop-in (the PWA has no OAuth callback).
- Push (APNs) is **best-effort awareness only**. The payload must not authorize.
  Foreground poll of `/api/pending` remains authoritative.
- APNs device tokens are stored on the **relay**, encrypted at rest; a hash is
  kept only for dedupe/logging. The daemon emits a `pending_event` on the
  control-plane WebSocket; the relay fans out. Missing Apple credentials →
  log-only fan-out (registration API still works).

## Non-goals

- OTP / TOTP / HOTP or any relay-trusted `{approved:true}` button
- Treating APNs, ntfy, or a push tap as authorization
- Replacing Mac Touch ID / localhost enroll
- Unifying Hermes in-run approvals or apple-tasks ntfy into this inbox

## Push provider

APNs (alert + optional background). Not FCM in v1. ntfy remains an optional
out-of-band ping, never the approval channel.
