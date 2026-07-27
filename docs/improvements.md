# Improvements log — review of the Phase 4–8 push

A tracking document for everything found and changed in the review cycle that
followed the rapid Phase 4–8 build-out (Cursor session, 2026-07-25), beyond
what a code diff shows. The build-out landed Phases 4 (phone relay) directly
on main and opened four sibling PRs (#1 Phase 7, #2 Phase 8, #3 Phase 5,
#4 Phase 6) all branched from the same commit (`f2660e7`).

Review and remediation: Claude (Fable 5 lead reviewer + Opus 5 work agents),
2026-07-26/27. Merged: PR #3 (squash `851b43d`), PR #5 (squash `0165a81`),
PR #4 reworked (squash `cf29c1f`).

Statuses: **FIXED** (merged to main) · **IN PROGRESS** (assigned) ·
**OPEN** (tracked, unassigned) · **PARKED** (deliberately deferred).

---

## 1. Security findings

### S1 — Approvals were not cryptographically bound to requests across the relay — FIXED (PR #5)

The most important finding. The project's core design principle is that the
approver *signs the request digest*. As shipped, the phone's WebAuthn
assertion signed a random webauthn-rs challenge; the digest↔ceremony pairing
lived only in the daemon's in-memory `auth_states` map. A compromised relay
could show the phone request A's summary while starting a ceremony for
request B — the user's genuine gesture then released B. Meanwhile
`relay.rs`'s header and `threat-model.md` both claimed a compromised relay
"cannot forge approvals," which was only true for forging-from-nothing, not
substitution.

Fix (`crates/gatehoused/src/binding.rs`): the ceremony challenge is now
derived deterministically — `SHA-256(JCS({digest, nonce,
purpose:"gatehouse-approval-v1"}))` — substituted into both the client
options and the webauthn-rs ceremony state, and re-derived at
`approve_finish` from the pending request actually being released, compared
constant-time against the challenge in the signed `clientDataJSON`. Fails
closed. A human-comparable verification code (first 8 hex of the digest,
computed daemon-side) is shown on the approval page and printed in the
daemon terminal's `APPROVAL NEEDED [xxxxxxxx]` line.

Honest residual risk (documented in threat-model.md): the relay serves the
PWA JavaScript, so a hostile relay can still deceive the *human* (show A,
start B, suppress the on-screen code). The code comparison defeats API-level
tampering; a native/pinned client (later phase) is the full fix.

### S2 — Passkey enrollment was gated by nothing but the page token — FIXED (PR #5)

`register_start/finish` required only the bearer token carried in the
approval-page URL (`?t=`). Anyone who obtained that URL could silently
enroll their own passkey and approve everything thereafter. Acceptable for
the Phase 2 localhost page (token in a 0600 file, loopback only); porting
the same model to an internet-reachable relay changed the risk class with no
added control.

Fix (`crates/gatehoused/src/enroll.rs`): enrolling now requires a one-time
code from `gate enroll-code`, printed on the operator's terminal — 8 chars,
CSPRNG with rejection sampling, ambiguity-free alphabet, single-use, 5-min
TTL, constant-time comparison. Enforced on both the localhost and phone
paths; covered by e2e on both.

### S3 — Phase 6 "multi-tenant" hosted mode shared one phone token across all tenants — FIXED (PR #4 rework, `cf29c1f`)

`devices.rs` stamped the *same* `phone_token` into every device credential;
phones authenticated with that single shared token plus a free-form `?d=`
device selector. Tenant A's phone could read tenant B's pending summaries,
deny tenant B's requests, and (before S2's fix) enroll a passkey against
tenant B's daemon. The old `resolve_device` also fell back to "the only
connected daemon," which crossed tenants even with no `?d=` at all.

Fix: each device gets its own CSPRNG `phone_token` at enrollment; the
presented bearer *is* the device selector (`devices::authorize_phone`), with
`?d=`/`X-Gatehouse-Device` demoted to a must-agree cross-check (403 on
mismatch). The relay-wide phone token authorizes only the legacy
single-tenant mTLS link and is refused against any enrolled device.
`DeviceRecord.phone_token` is deliberately not `serde(default)`, so a
pre-change `devices.json` fails loudly instead of loading an empty secret.
E2e enrolls two tenants and proves isolation in both directions;
fault-injected (making the relay trust `?d=` breaks the test).

### S4 — mTLS Hello remap allowed device_id spoofing — FIXED (PR #4 rework, `cf29c1f`)

An mTLS-authenticated daemon connection could claim any enrolled
`device_id` via its Hello message without presenting that device's token
(`relay.rs` Hello handler). Fix: remap deleted outright — the mTLS channel
identity is pinned to the legacy single-tenant `_mtls` device and a
mismatching Hello only draws a warning.

### S5 — Secrets compared with `==` — FIXED (PR #5 + PR #4 rework)

`web.rs::authed` (localhost page token) and `relay.rs` (phone token) use
`subtle` constant-time comparison since PR #5. `devices::lookup_token` on
the phase-6 branch (early-exit string match) is now a constant-time
scan-all-records `select()` shared by both the control-plane and phone-token
lookups (`cf29c1f`).

### S6 — Nonces were timestamp-derived — FIXED (PR #5)

`server.rs::new_nonce` was two timestamp components with a comment promising
a CSPRNG "in phase 2+" (still there at phase 6). Now 32 CSPRNG bytes, hex.
The nonce participates in challenge derivation (S1), so this stopped being
cosmetic.

### S7 — "Forged approval rejected" e2e tests proved less than their names claimed — FIXED (PR #5 + PR #4 rework)

Both the phase-4 and phase-6 "forged approval without WebAuthn assertion is
rejected" tests exercised `reject_unauthenticated_release` — a JSON *shape*
check (missing `cred` key → 401). The real defense
(`finish_passkey_authentication` + now `check_bound`) was untested. PR #5
added unit tests for the binding path including the digest-swap and
nonce-swap cases with synthetic credentials. The PR #4 rework renamed both
e2e tests to say what they test ("a finish body with no assertion is
rejected at the relay") and added hosted-path coverage proving enrollment
codes and the verification code survive the hosted dispatch.

## 2. Correctness findings (fixed in PR #3's hardening commits)

- **gate-mcp dropped or mis-answered JSON-RPC notifications.** Only two
  hardcoded method names were treated as notifications; anything else
  without an id (e.g. `notifications/cancelled`, which real MCP clients
  send) drew a `-32601` error with `id: null` — a protocol violation.
  Dispatch now keys on presence of `id`/`method`.
- **gated_fetch followed redirects to hosts policy never cleared.** A
  policy-allowed host could 302 to anywhere. Redirects are no longer
  followed; the tool returns the Location and tells the caller to re-fetch
  so policy sees the new host.
- **gated_fetch could panic on truncation.** Byte-offset slicing at 32,000
  could split a UTF-8 character and kill the server. Now char-boundary-safe.
- **gated_fetch accepted non-http(s) schemes** that have no host for policy
  to match. Now rejected.
- **`gate audit verify` was correct but unproven.** It did recompute entry
  hashes (initial review suspicion refuted), but the only test was
  `empty_file_ok`. Added: tampered-body-with-intact-linkage (the attack
  linkage-only checking misses), first-entry tamper, broken linkage,
  dropped-genesis, plus an e2e that tampers a real audit log.
- **gate-mcp's Pending-decision path was untested.** The logic was correct
  (kept reading after `Decision{Pending}`), but nothing verified it. Added
  an e2e with approval mid-flight; the assertion was verified by fault
  injection (breaking the Pending arm makes it fail) and tightened so a
  timeout-denial cannot false-pass it.
- **Stale duplicate policy file.** The policy move to `gatehouse-proto` left
  `crates/gatehoused/default_policy.toml` behind as a second live copy that
  could silently drift from the compiled one. Deleted.
- **docker-compose recipe could never have worked**: the agent service ran
  `cargo install` under `network_mode: none`. Split into a networked build
  stage and a no-network agent service.
- **Dead dependencies** left behind by the policy/audit move (`sha2`,
  `serde_jcs`, `toml` in gatehoused; `serde` in gate-mcp). Removed.
- **Clippy drift**: main carried 3 warnings; the PR added a 4th. All zero
  now.

## 3. Documentation honesty

- `docs/threat-model.md` originally claimed the relay was "Transport only —
  must not be able to forge approvals." Rewritten (PR #3) to state the real
  guarantee, then updated again (PR #5) after the binding fix landed, with
  the residual-risk example corrected at review (`show A / start B /
  suppress the code`, not the honest flow).
- `relay.rs` and `gatehouse-proto/src/relay.rs` module headers repeated the
  overclaim; `web.rs`'s header said binding "will" arrive in phase 4 (it
  hadn't). All corrected in PR #5.
- Adapter READMEs: the OpenCode plugin fails open on an "ask" decision when
  the daemon is down (falls back to OpenCode's own prompting) — reasonable,
  but undocumented. Flagged for PR #1 before it merges.

## 4. Process findings

- **Four sibling PRs off one base commit, with overlapping files.**
  `tests/e2e.sh` modified in all four; `crates/gate/src/main.rs` in three;
  `hook.rs` in two. Each showed MERGEABLE individually, but merging any one
  invalidates the others — and PR #3 *moved the policy engine between
  crates* while PR #2 rewired the daemon against the old layout, making the
  conflicts semantic, not just textual. Should have been a stacked train.
  Resolution: sequential review pipeline (5 → 4-hardening → 6), PRs #1/#2
  parked pending rebase.
- **Phases built in the wrong order.** The threat model (Phase 5) was
  supposed to inform relay-exposure decisions; instead Phases 6–8 were built
  speculatively first, and the threat model that resulted mischaracterized
  the relay guarantee (S1). Phases 7–9 were roadmap sketches, not scheduled
  work.
- **Inconsistent conventions**: Phase 4 and the roadmap commit went directly
  to main; Phases 5–8 got PRs. The working tree was left checked out on a
  feature branch.
- **PR #1's Codex adapter writes `~/.codex/hooks.json` with
  Claude-Code-style PreToolUse matchers** — an integration surface ported by
  analogy, not verified against a real Codex install. PARKED until verified.

## 5. Tooling incident (affects more than this repo)

During the review, the `rtk` command wrapper returned **false data** to a
work agent: `git status` reported a dirty tree (8 modified files) as clean;
`cat` served the committed HEAD version of a file instead of the working-tree
version; `wc -l < file` returned 0; and `git diff HEAD > backup.patch`
silently wrote rtk's summary format instead of a real patch, corrupting a
backup. Ground truth required `rtk proxy git ...` and native file reads.
Worth investigating in rtk itself before it corrupts another workflow —
token-optimized output must never change the *content* of state-inspection
commands.

## 6. Remaining work

- [x] **PR #4 rework**: merged as `cf29c1f` — S3/S4/S5/S7 closed; enrollment
      codes and challenge binding proven through hosted mode; two-tenant
      isolation e2e in both directions.
- [ ] **PR #1 (parked)**: verify the Codex hooks surface actually exists;
      document OpenCode fail-open; rebase.
- [ ] **PR #2 (parked)**: rebase onto post-#3 layout (policy now lives in
      gatehouse-proto); apply constant-time treatment to the TCP IPC
      `AUTH <token>` line.
- [ ] Native/pinned approval client to close S1's residual risk (roadmap
      Phase 9).

## 7. Minor residuals noted during the PR #4 rework (accepted, unassigned)

- `--relay-url` + `--relay-token` one-shot mode carries no phone token
  (`DialConfig::resolve` sets `phone_token: None`), so the daemon prints the
  localhost page URL instead of the hosted one. The `device.json` path is
  the fully-featured route.
- `gatehoused device-enroll --write` overwrites an existing `device.json` —
  fine for one broker per machine, a footgun when enrolling several devices
  from the same host (enroll without `--write` and use `device-cred` there).
- The relay reads `devices.json` from disk on every phone API call: a
  blocking read inside an async handler. Small file, and it means new
  enrollments apply without a relay restart; revisit if the device count
  grows.
