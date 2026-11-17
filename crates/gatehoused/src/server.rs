//! Agent-socket handling: the submit → decide → (maybe) execute pipeline.

use std::sync::Arc;

use base64::Engine;
use gatehouse_proto::{
    AgentMsg, ApprovalEnvelope, DaemonMsg, DecisionStatus, GateRequest, Operation, SigScheme, Tier,
};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::audit::now_unix;
use crate::ipc::{self, LocalListener};
use crate::state::Pending;
use crate::Ctx;

type Writer = Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>>;

async fn send(w: &Writer, msg: &DaemonMsg) {
    let mut line = serde_json::to_string(msg).expect("serializable");
    line.push('\n');
    let _ = w.lock().await.write_all(line.as_bytes()).await;
}

pub async fn run(listener: LocalListener, ctx: Arc<Ctx>) {
    loop {
        match ipc::accept(&listener).await {
            Ok((read, write)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let w: Writer = Arc::new(tokio::sync::Mutex::new(write));
                    let mut lines = BufReader::new(read).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        match serde_json::from_str::<AgentMsg>(&line) {
                            Ok(AgentMsg::Submit { request, execute }) => {
                                handle_submit(&w, &ctx, request, execute).await;
                            }
                            Err(e) => {
                                send(
                                    &w,
                                    &DaemonMsg::Error {
                                        message: format!("bad message: {e}"),
                                    },
                                )
                                .await;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                warn!("agent ipc accept failed: {e}");
            }
        }
    }
}

async fn handle_submit(w: &Writer, ctx: &Arc<Ctx>, request: GateRequest, execute: bool) {
    let digest = match request.digest() {
        Ok(d) => d,
        Err(e) => {
            send(
                w,
                &DaemonMsg::Error {
                    message: e.to_string(),
                },
            )
            .await;
            return;
        }
    };
    let summary = request.summary();
    let (mut tier, mut rule) = ctx.policy.resolve(&request);

    if grant_lifts(&ctx.state, tier, &request.op) {
        tier = Tier::Allow;
        rule = "session grant".into();
    }

    let decision = |status| DaemonMsg::Decision {
        digest: digest.clone(),
        tier,
        status,
        summary: summary.clone(),
    };

    match tier {
        Tier::Deny => {
            info!("deny [{}] {summary} ({rule})", &digest[..8]);
            ctx.audit(&digest, &summary, tier, "denied", &rule);
            send(w, &decision(DecisionStatus::Denied)).await;
        }
        Tier::Allow => {
            info!("allow [{}] {summary} ({rule})", &digest[..8]);
            ctx.audit(&digest, &summary, tier, "allowed", &rule);
            send(w, &decision(DecisionStatus::Allowed)).await;
            if execute {
                run_child(w, &request).await;
            }
        }
        Tier::Ask | Tier::AskStrong => {
            let (tx, rx) = oneshot::channel();
            let nonce = new_nonce();
            let duplicate = {
                let mut pending = ctx.state.pending.lock().unwrap();
                if pending.contains_key(&digest) {
                    true
                } else {
                    pending.insert(
                        digest.clone(),
                        Pending {
                            request: request.clone(),
                            tier,
                            nonce: nonce.clone(),
                            submitted: std::time::Instant::now(),
                            tx,
                        },
                    );
                    false
                }
            };
            if duplicate {
                send(
                    w,
                    &DaemonMsg::Error {
                        message: "identical request already pending approval".into(),
                    },
                )
                .await;
                return;
            }
            ctx.audit(&digest, &summary, tier, "pending", &rule);
            send(w, &decision(DecisionStatus::Pending)).await;
            let _ = ctx.pending_wake.send(crate::PendingWake {
                digest_prefix: digest[..8].to_string(),
                summary: summary.clone(),
                tier: format!("{tier:?}").to_ascii_lowercase(),
                harness: request.harness.clone(),
            });
            let short = &digest[..8];
            if tier == Tier::AskStrong && ctx.passkeys_enrolled() {
                if let Some(url) = ctx.approval_url() {
                    // `short` is the verification code the approval page
                    // shows; the human compares the two.
                    warn!(
                        "APPROVAL NEEDED [{short}] {summary} — passkey required; \
                         confirm the approval page shows code {short}: {url}"
                    );
                    if ctx.auto_open {
                        open_browser(&url);
                    }
                } else {
                    warn!("APPROVAL NEEDED [{short}] {summary} — approval page not up yet");
                }
            } else {
                warn!("APPROVAL NEEDED [{short}] {summary} — run: gate approve {short}");
                if tier == Tier::AskStrong {
                    warn!(
                        "[{short}] tier is ask-strong but no passkey is enrolled; \
                         operator approval will be recorded as unattested \
                         (run `gate enroll` to fix)"
                    );
                }
            }

            let approval = match tokio::time::timeout(ctx.approval_timeout, rx).await {
                Ok(Ok(Some(envelope))) => {
                    // Bind the approval to this exact request before release.
                    let structurally_ok = envelope.check(&digest, now_unix()).is_ok();
                    let nonce_ok = envelope.nonce == nonce;
                    if !structurally_ok || !nonce_ok {
                        warn!("[{short}] approval envelope rejected (binding/expiry)");
                        None
                    } else {
                        Some(envelope)
                    }
                }
                Ok(Ok(None)) => None,
                // Sender dropped (daemon-side denial path) or timeout.
                Ok(Err(_)) => None,
                Err(_) => {
                    ctx.state.pending.lock().unwrap().remove(&digest);
                    warn!("[{short}] approval timed out; denying");
                    None
                }
            };

            // Defence in depth for the ctl-side check: an unattested envelope
            // never releases an ask-strong request while a passkey exists.
            let approval = approval.filter(|env| {
                let ok = !(tier == Tier::AskStrong
                    && env.scheme == SigScheme::None
                    && ctx.passkeys_enrolled());
                if !ok {
                    warn!(
                        "[{short}] unattested approval refused for ask-strong (passkey enrolled)"
                    );
                }
                ok
            });

            if let Some(envelope) = approval {
                let (outcome, via) = approval_audit_label(tier, &envelope);
                info!("{outcome} [{short}] {summary} via {via}");
                ctx.audit(&digest, &summary, tier, outcome, &via);
                send(w, &decision(DecisionStatus::Allowed)).await;
                if execute {
                    run_child(w, &request).await;
                }
            } else {
                info!("denied [{short}] {summary}");
                ctx.audit(&digest, &summary, tier, "denied", "operator");
                send(w, &decision(DecisionStatus::Denied)).await;
            }
        }
    }
}

/// Session grants lift `ask` to `allow` for exec ops and nothing else. They are
/// created over the ctl socket without any attestation, so letting one lift
/// `ask_strong` would let anything that reaches ctl (`gate grant "git push*"`)
/// stand in for the passkey. Deny is never lifted either.
fn grant_lifts(state: &crate::state::Shared, tier: Tier, op: &Operation) -> bool {
    if tier != Tier::Ask {
        return false;
    }
    match op {
        Operation::Exec { argv, .. } => state.grant_matches(&argv.join(" ")),
        _ => false,
    }
}

/// Audit `(decision, via)` for a released request. Operator ctl approvals
/// carry no signature; an ask-strong one only happens when no passkey is
/// enrolled (the documented fallback) and gets its own decision string so
/// it cannot be mistaken for an attested release when reading the log.
fn approval_audit_label(tier: Tier, envelope: &ApprovalEnvelope) -> (&'static str, String) {
    match (envelope.scheme, tier) {
        (SigScheme::None, Tier::AskStrong) => (
            "approved-unattested",
            format!(
                "{} (unattested: ask-strong approved without a passkey; none enrolled)",
                envelope.key_id
            ),
        ),
        (SigScheme::None, _) => ("approved", format!("{} (unattested)", envelope.key_id)),
        (scheme, _) => ("approved", format!("{scheme:?}:{}", envelope.key_id)),
    }
}

/// Environment variables always passed through to children, on top of the
/// request's explicit allowlist.
const BASE_ENV: &[&str] = &["PATH", "HOME", "TERM", "LANG", "USER", "SHELL", "TMPDIR"];

/// Broker-executes: the daemon runs the approved argv itself and streams
/// output back. The agent never gets to run the command in its own context.
async fn run_child(w: &Writer, request: &GateRequest) {
    let Operation::Exec { argv, cwd } = &request.op else {
        return;
    };
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(cwd)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for key in BASE_ENV
        .iter()
        .copied()
        .chain(request.env_allowlist.iter().map(String::as_str))
    {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            send(
                w,
                &DaemonMsg::Error {
                    message: format!("spawn failed: {e}"),
                },
            )
            .await;
            send(w, &DaemonMsg::Exit { code: 127 }).await;
            return;
        }
    };

    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let (out_w, err_w) = (w.clone(), w.clone());
    let out_task = tokio::spawn(async move {
        pump(&mut stdout, &out_w, false).await;
    });
    let err_task = tokio::spawn(async move {
        pump(&mut stderr, &err_w, true).await;
    });
    let _ = out_task.await;
    let _ = err_task.await;
    let code = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(-1);
    send(w, &DaemonMsg::Exit { code }).await;
}

async fn pump<R: tokio::io::AsyncRead + Unpin>(reader: &mut R, w: &Writer, is_err: bool) {
    use tokio::io::AsyncReadExt;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut buf = vec![0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let data = b64.encode(&buf[..n]);
                let msg = if is_err {
                    DaemonMsg::Stderr { b64: data }
                } else {
                    DaemonMsg::Stdout { b64: data }
                };
                send(w, &msg).await;
            }
        }
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

/// Unpredictable per pending approval: the nonce feeds the derived WebAuthn
/// ceremony challenge, so guessing it would let a challenge be precomputed.
fn new_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use gatehouse_proto::{CtlMsg, CtlResp, Policy};
    use tokio::io::AsyncReadExt;

    use crate::state::Grant;

    fn default_policy() -> Policy {
        toml::from_str(gatehouse_proto::policy::DEFAULT_POLICY).unwrap()
    }

    fn exec(argv: &[&str]) -> GateRequest {
        GateRequest {
            harness: "test".into(),
            session_id: "s".into(),
            env_allowlist: vec![],
            op: Operation::Exec {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: std::env::temp_dir().to_string_lossy().into_owned(),
            },
        }
    }

    /// Run one submit to completion and return every message the daemon sent.
    async fn submit(ctx: &Arc<Ctx>, req: GateRequest, execute: bool) -> Vec<DaemonMsg> {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let w: Writer = Arc::new(tokio::sync::Mutex::new(Box::new(server)));
        handle_submit(&w, ctx, req, execute).await;
        drop(w);
        let mut buf = String::new();
        client.read_to_string(&mut buf).await.unwrap();
        buf.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn statuses(msgs: &[DaemonMsg]) -> Vec<(Tier, DecisionStatus)> {
        msgs.iter()
            .filter_map(|m| match m {
                DaemonMsg::Decision { tier, status, .. } => Some((*tier, *status)),
                _ => None,
            })
            .collect()
    }

    fn grant(ctx: &Arc<Ctx>, glob: &str) -> CtlResp {
        crate::ctl::handle(
            ctx,
            CtlMsg::Grant {
                argv_glob: glob.into(),
                ttl_secs: 60,
            },
            Instant::now(),
        )
    }

    fn last_audit_decision(path: &std::path::Path) -> (String, String) {
        let text = std::fs::read_to_string(path).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        (
            v["decision"].as_str().unwrap().to_string(),
            v["rule"].as_str().unwrap().to_string(),
        )
    }

    /// Regression: `gate grant "*"` used to lift every ask-strong request to
    /// allow, bypassing the passkey entirely.
    #[tokio::test]
    async fn grant_star_is_rejected() {
        let (ctx, _) = crate::test_ctx(default_policy(), Duration::from_millis(100), vec![]);
        assert!(matches!(grant(&ctx, "*"), CtlResp::Error { .. }));
        assert!(matches!(grant(&ctx, "* *"), CtlResp::Error { .. }));
        assert!(ctx.state.grant_snapshot().is_empty());
    }

    #[tokio::test]
    async fn grants_never_lift_ask_strong() {
        let (ctx, _) = crate::test_ctx(default_policy(), Duration::from_millis(100), vec![]);
        // A validated grant naming the program exactly...
        assert!(matches!(grant(&ctx, "git push*"), CtlResp::Ok { .. }));
        // ...and even a `*` grant planted behind validation's back.
        ctx.state.grants.lock().unwrap().push(Grant {
            argv_glob: "*".into(),
            expires: Instant::now() + Duration::from_secs(60),
        });
        let msgs = submit(&ctx, exec(&["git", "push", "origin", "main"]), false).await;
        assert_eq!(
            statuses(&msgs),
            vec![
                (Tier::AskStrong, DecisionStatus::Pending),
                (Tier::AskStrong, DecisionStatus::Denied)
            ],
            "ask-strong must stay pending and time out, never be granted"
        );
        // Deny is not liftable either.
        let msgs = submit(&ctx, exec(&["sudo", "ls"]), false).await;
        assert_eq!(statuses(&msgs), vec![(Tier::Deny, DecisionStatus::Denied)]);
    }

    #[tokio::test]
    async fn grants_still_lift_plain_ask() {
        let (ctx, _) = crate::test_ctx(default_policy(), Duration::from_millis(100), vec![]);
        assert!(matches!(grant(&ctx, "frobnicate *"), CtlResp::Ok { .. }));
        let msgs = submit(&ctx, exec(&["frobnicate", "x"]), false).await;
        assert_eq!(
            statuses(&msgs),
            vec![(Tier::Allow, DecisionStatus::Allowed)]
        );
    }

    /// Spawn a submit, wait for it to be pending, return its digest.
    async fn spawn_pending(
        ctx: &Arc<Ctx>,
        req: GateRequest,
    ) -> (String, tokio::task::JoinHandle<Vec<DaemonMsg>>) {
        let digest = req.digest().unwrap();
        let c = ctx.clone();
        let task = tokio::spawn(async move { submit(&c, req, false).await });
        for _ in 0..200 {
            if ctx.state.pending.lock().unwrap().contains_key(&digest) {
                return (digest, task);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("request never became pending");
    }

    /// No passkey enrolled: ctl approval of ask-strong is the documented
    /// fallback, and the audit log must say it was unattested.
    #[tokio::test]
    async fn unattested_ask_strong_approval_is_labelled_in_audit() {
        let (ctx, audit) = crate::test_ctx(default_policy(), Duration::from_secs(5), vec![]);
        let (digest, task) = spawn_pending(&ctx, exec(&["git", "push"])).await;
        let resp = crate::ctl::handle(
            &ctx,
            CtlMsg::Approve {
                digest_prefix: digest[..8].into(),
            },
            Instant::now(),
        );
        assert!(matches!(resp, CtlResp::Ok { .. }), "{resp:?}");
        let msgs = task.await.unwrap();
        assert_eq!(statuses(&msgs).last().unwrap().1, DecisionStatus::Allowed);
        let (decision, rule) = last_audit_decision(&audit);
        assert_eq!(decision, "approved-unattested");
        assert!(rule.contains("unattested"), "{rule}");
    }

    #[tokio::test]
    async fn unattested_plain_ask_approval_says_so_in_audit() {
        let (ctx, audit) = crate::test_ctx(default_policy(), Duration::from_secs(5), vec![]);
        let (digest, task) = spawn_pending(&ctx, exec(&["frobnicate"])).await;
        crate::ctl::handle(
            &ctx,
            CtlMsg::Approve {
                digest_prefix: digest[..8].into(),
            },
            Instant::now(),
        );
        task.await.unwrap();
        let (decision, rule) = last_audit_decision(&audit);
        assert_eq!(decision, "approved");
        assert_eq!(rule, "operator-ctl (unattested)");
    }

    /// With a passkey enrolled the ctl path refuses ask-strong, and an
    /// unattested envelope pushed straight at the waiter is refused too.
    #[tokio::test]
    async fn passkey_enrolled_refuses_unattested_ask_strong() {
        let pk = crate::relay_client::tests::synthetic_passkey();
        let (ctx, audit) = crate::test_ctx(default_policy(), Duration::from_secs(5), vec![pk]);
        let (digest, task) = spawn_pending(&ctx, exec(&["git", "push"])).await;
        let resp = crate::ctl::handle(
            &ctx,
            CtlMsg::Approve {
                digest_prefix: digest[..8].into(),
            },
            Instant::now(),
        );
        assert!(matches!(resp, CtlResp::Error { .. }), "{resp:?}");

        let (_, pending) = ctx.state.take_pending(&digest).unwrap();
        let now = crate::audit::now_unix();
        let _ = pending.tx.send(Some(ApprovalEnvelope {
            digest: digest.clone(),
            nonce: pending.nonce.clone(),
            issued_at: now,
            expires_at: now + 60,
            key_id: "operator-ctl".into(),
            scheme: SigScheme::None,
            sig: String::new(),
        }));
        let msgs = task.await.unwrap();
        assert_eq!(statuses(&msgs).last().unwrap().1, DecisionStatus::Denied);
        assert_eq!(last_audit_decision(&audit).0, "denied");
    }
}
