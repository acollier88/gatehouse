# Gatehouse — harness-agnostic approval broker for AI coding agents

Working name: **gatehouse** (rename freely; check crates.io/GitHub availability before publishing).

## Context

Sandboxed coding agents today either get blanket permissions or rubber-stamp-prone in-terminal prompts that share a channel with the agent itself. The pieces of a better answer all exist separately in 2026 — enterprise CIBA approval (Auth0/Okta), hobbyist phone-approval hooks for Claude Code (claude-push, ntfy hooks, all with weak security), and commodity sandboxes — but nothing integrates them for local coding agents. Gatehouse fills that gap: an open-source, harness-agnostic broker where risky agent operations require a cryptographically request-bound approval signed by a human-presence gesture (Touch ID first, phone passkey next). The agent cannot approve its own requests, and an approval for one request cannot be replayed or swapped onto another.

Design principles established during research (non-negotiable in implementation):

1. **Enforce at the sandbox boundary, not hooks.** Harness hooks are adapters/UX; the security story assumes the sandbox denies everything and the broker socket is the only escape hatch. Hook-only mode is explicitly documented as "advisory mode."
2. **Approval is bound to the request.** The approver signs `SHA-256(canonical_request) + nonce + expiry` with a hardware-backed key. The broker verifies the signature against the exact request it is about to release. No bare OTPs.
3. **Prefer broker-executes over broker-permits** where the integration allows (kills TOCTOU). Where the harness must execute (Claude Code hooks), document the weaker guarantee.
4. **Fight approval fatigue with policy tiers.** Biometric prompts are reserved for genuinely dangerous ops; workspace-scoped edits auto-pass; session-scoped grants ("allow `npm install` for 1h") reduce repeat prompts.

## Deliverable

New Rust workspace at `~/Code/gatehouse` (new git repo — current cwd `~/Code/sass` is unrelated):

```
gatehouse/
  Cargo.toml            # workspace
  crates/
    gatehoused/         # host daemon: policy engine, approval channels, audit log, UDS server
    gate/               # client CLI: `gate run -- <cmd>`, `gate ask`, `gate grant`, status
    gatehouse-proto/    # shared types: canonical request format, wire protocol, signature envelope
    gatehouse-macos/    # Touch ID / Secure Enclave signer (objc2 / security-framework bindings)
  adapters/
    claude-code/        # PreToolUse hook script + settings snippet
    mcp-gateway/        # (phase 5) MCP server exposing gated tools
  docs/
```

## Phases

### Phase 1 — Core daemon, protocol, policy engine (terminal approvals)
- `gatehouse-proto`: canonical request type — `{kind: exec|file_write|net, argv/path/host, cwd, env_allowlist, harness, session_id}` serialized via canonical JSON (RFC 8785-style; use the `serde_jcs` crate) → SHA-256 digest. Signature envelope: `{digest, nonce, issued_at, expires_at, sig, key_id}`.
- `gatehoused`: tokio UDS server at `$XDG_RUNTIME_DIR/gatehouse.sock` (0600). JSON-RPC-ish request/response with long-poll for pending decisions.
- Policy engine: TOML at `~/.config/gatehouse/policy.toml` with four tiers: `allow`, `ask` (local terminal y/n in v1), `ask-strong` (signed approval), `deny`. Matchers: argv[0] + arg globs, path prefixes (workspace scoping), network host globs. Ship a conservative default policy (workspace file ops → allow; `git push`, `rm -rf` outside workspace, `curl|sh` patterns, credential paths → ask-strong; `sudo` → deny). Do NOT attempt full shell parsing; canonicalize argv only and treat `bash -c`/`sh -c` as opaque → ask-strong by default.
- `gate run -- <cmd>`: client submits request, daemon decides, and on approval **the daemon executes** (fork/exec as the daemon's user, streams stdout/stderr back over the socket). This is the broker-executes path.
- Session grants: `gate grant "npm install" --for 1h` writes a TTL'd in-memory grant.
- Append-only JSONL audit log (`~/.local/share/gatehouse/audit.jsonl`), each entry hash-chained to the previous.

### Phase 2 — Strong approval: passkeys (WebAuthn) + Touch ID (`ask-strong` becomes real)
- **Passkey path (primary):** the daemon serves a localhost-only approval page (embedded HTTP on `127.0.0.1`, random port + bearer token). `gate enroll` opens it to register a passkey with the platform authenticator — on macOS that is Touch ID via WebAuthn, elsewhere whatever platform authenticator exists, so this path stays OS-agnostic. An `ask-strong` request pops the page, which displays the canonical summary and requests a WebAuthn assertion whose challenge is the request digest envelope. Daemon verifies with `webauthn-rs`. **Phase 4 reuses this exact enrollment + verification stack over a relay for phones** — the phase 4 delta is transport (relay + Web Push), not crypto.
- **Native Secure Enclave signer (secondary/optional):** `gatehouse-macos` crate — SE P-256 key (`kSecAttrTokenIDSecureEnclave`, `biometryCurrentSet`) with `LAContext` prompt carrying the canonical summary. Both back the same signer/verifier trait, so either can satisfy `ask-strong`.
- Falls back to operator terminal approval if nothing is enrolled (with loud warning).

### Phase 3 — Claude Code adapter
- PreToolUse hook (Bash + Write/Edit matchers) that shells to `gate ask --harness claude-code --json` and maps decision → hook allow/deny output. Blocks until decision or timeout (configurable, default deny on timeout).
- Docs must state plainly: hook mode is advisory (harness executes; bypassable if sandbox is off). Recommended deployment: Claude Code sandbox mode ON + hook, or agent inside a container whose only network/exec route is `gate run`.
- Ship `adapters/claude-code/install.sh` that adds the hook to `.claude/settings.json`.

### Phase 4 — Phone approval (PWA + relay, WebAuthn)
- Minimal relay: single Rust binary (`gatehoused --relay` mode or separate `gatehouse-relay`) the user self-hosts (or exposes via Tailscale Funnel). Daemon ↔ relay over mTLS; phone ↔ relay serves a static PWA.
- PWA: enroll a passkey (WebAuthn platform authenticator → FaceID/fingerprint), receive pending requests via Web Push, display canonical summary, sign challenge = request digest envelope via WebAuthn assertion. Daemon verifies assertion (crate: `webauthn-rs`) against enrolled credential.
- ntfy.sh is NOT used for the approval path (only optionally for informational pings). The approval channel is end-to-end verified by signature, so relay compromise ≠ approval forgery.

### Phase 5 — Broader harness surface + polish
- MCP gateway adapter: expose `gated_exec`, `gated_fetch` MCP tools so any MCP-capable harness routes through the broker.
- Generic docs/recipes: OpenCode, Codex CLI, containerized agent with socket-only egress (docker-compose example mounting the UDS).
- `gate audit verify` (hash-chain check), `gate policy test -- <cmd>` (dry-run tier resolution), README with threat model section (explicitly listing what hook-mode does NOT protect against).

### Phase 6 — Hosted / integrator relay
- Multi-tenant relay endpoint so integrators (Cursor, Claude, Codex, Pi, …) or enterprises can publish a stable phone RP (`approve.example.com`) without requiring every user to run Tailscale.
- Daemon config: `endpoint = <integrator | self-hosted URL>`; device enrollment replaces shared CA files for SaaS; ceremonies remain on the user broker (relay still cannot forge approvals).
- Setup UX already started in Phase 4: `relay-init` asks Tailscale vs custom hostname and supports re-setup with `--force` (RP ID change ⇒ re-enroll passkeys).
- Spec: [docs/hosted-relay.md](hosted-relay.md).

### Phase 7 — More harness adapters (Claude Code pattern)
- Ship out-of-tree adapters under `adapters/` the way Phase 3 did for Claude Code: hook / wrapper / MCP client that calls `gate ask` or `gate hook <name>`, with install scripts and an honesty section (advisory vs enforced).
- Priority targets (exact hook surfaces vary; research per tool):
  - **Open-ish / scriptable:** OpenCode, Codex CLI, Aider, Continue, Goose, Pi — prefer PRs upstream where the project is OSS and receptive.
  - **Closed / no upstream PR path:** Cursor Agent, Claude Code (done), ChatGPT/Codex app, proprietary IDE agents — adapters only; document the ceiling (harness must honor the hook or route exec through `gate run`).
- Shared adapter kit: stdin JSON → `GateRequest` classifiers, timeout/deny defaults, settings merge helpers (generalize `adapters/claude-code/install.sh`).
- MCP gateway from Phase 5 is the portable escape hatch when a harness has no hook API but can call MCP tools.

### Phase 8 — Windows + Linux hosts for `gatehoused`
- Goal: broker + CLI + policy + localhost WebAuthn on Windows and Linux; **phone relay may stay Unix-first** initially (mTLS + Funnel/Tailscale recipes are macOS/Linux ops-heavy).
- Replace Unix-domain sockets with a platform transport: Windows named pipes (or loopback TCP + token) for agent/ctl; keep the same JSON wire protocol.
- Platform authenticators: Linux (`libfido2` / browser passkey via localhost page — already mostly OK); Windows Hello via the same WebAuthn page (Edge/Chrome).
- CI matrix: `ubuntu-latest` + `windows-latest` unit/e2e for `gate run` / policy / audit (relay e2e optional/nightly).
- Docs: path overrides (`GATEHOUSE_*`), service install notes (systemd user unit; Windows service or tray later).

### Phase 9 — Dedicated approval / MFA app (research → spike)
*Intentionally underbaked — revisit with a clear threat model before committing to a store app.*

Open questions to answer first:
1. **Is a custom app required?** Today’s path is browser PWA + platform passkey. A native app mainly wins on push reliability, UX, and App Store discovery — not on crypto strength if WebAuthn stays.
2. **Reuse vs build:** survey OSS “push approval” apps (e.g. authenticator-style, CIBA/demo clients, privacy-preserving push). Prefer **passkeys / OS WebAuthn** over reinventing TOTP/HOTP; do not become another OTP broker.
3. **Plugin to existing authenticators?** Standard passkeys already use iCloud Keychain / Google Password Manager / 1Password / etc. A Gatehouse app would be for **pending-request UX + push**, with assertion still WebAuthn against the relay RP — not a proprietary soft-token.
4. **Push shape:** relay/hosted endpoint → APNs/FCM “approval needed” → app opens ceremony or in-app WebAuthn → assertion back to relay → daemon verifies. Push payload must not authorize anything by itself.
5. **Scope cut:** spike a thin iOS/Android shell that wraps the existing PWA + Web Push before designing a greenfield MFA protocol.

Exit criteria for leaving “research”: written decision (PWA-only vs thin native shell vs full app), push provider choice, and explicit non-goals (no OTP, no relay-trusted approve button).

## Key implementation notes
- Rust edition 2024; workspace deps: `tokio`, `serde`/`serde_jcs`, `sha2`, `p256`, `webauthn-rs` (phase 4), `security-framework`/`objc2` (phase 2), `clap`.
- The Unix socket is the trust boundary: daemon runs as the user (v1); document the future hardening path (separate user / host-side daemon for containerized agents).
- Nonces are daemon-generated per request; envelopes expire in 120s; daemon persists spent nonces for the expiry window to block replays.
- Canonical-summary rendering must be the same function feeding both the digest and every approval UI — no summary/digest divergence.

## Verification
- **Phase 1:** unit tests for policy tier resolution + canonical digest stability; integration test: `gate run -- echo hi` auto-allows; `gate run -- git push` blocks pending approval; second daemon-side approval releases it; audit chain verifies.
- **Phase 2:** manual: `gate enroll` then a `git push` triggers Touch ID with correct summary; test that a tampered request (digest mismatch) is rejected even with a valid signature from another request (replay test in CI using a software P-256 key behind the same signer trait).
- **Phase 3:** sample repo with hook installed; run Claude Code, ask it to `git push`; confirm hook blocks until Touch ID approval; timeout path denies.
- **Phase 4:** phone enrolls passkey; kill relay mid-approval → request denied on timeout; forged relay message without valid WebAuthn assertion → rejected.
- **Phase 6:** two daemons enrolled to one hosted relay cannot approve each other’s requests; relay “approved” without assertion rejected; migrating RP ID forces re-enrollment.
- **Phase 7:** at least one additional adapter (OSS preferred) green in e2e; closed-tool adapter docs state advisory ceiling; shared classifier helpers used by ≥2 adapters.
- **Phase 8:** `cargo test` + smoke e2e on Linux and Windows CI without Unix-only APIs in the broker core; sockets/pipes abstracted behind one trait.
- **Phase 9:** research note checked into `docs/` with go/no-go; if go, spike app that completes one real `ask-strong` via existing relay crypto.
