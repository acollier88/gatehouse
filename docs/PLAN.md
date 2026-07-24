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

### Phase 2 — Touch ID signer (`ask-strong` becomes real)
- `gatehouse-macos`: Secure Enclave P-256 key via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` + access control `biometryCurrentSet` (crates: `security-framework`, `objc2-local-authentication`). `gate enroll` creates the key; the daemon triggers `LAContext` prompt showing the human-readable request summary, signs the digest envelope, verifies, releases.
- Approval UI: native macOS prompt text carries the canonical summary ("Run `git push origin main` in ~/Code/foo"). Falls back to terminal y/n if no enrolled key (with loud warning).

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
