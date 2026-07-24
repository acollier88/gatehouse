//! Agent-socket handling: the submit → decide → (maybe) execute pipeline.

use std::sync::Arc;

use base64::Engine;
use gatehouse_proto::{
    AgentMsg, DaemonMsg, DecisionStatus, GateRequest, Operation, Tier,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::audit::now_unix;
use crate::state::Pending;
use crate::Ctx;

type Writer = Arc<tokio::sync::Mutex<OwnedWriteHalf>>;

async fn send(w: &Writer, msg: &DaemonMsg) {
    let mut line = serde_json::to_string(msg).expect("serializable");
    line.push('\n');
    let _ = w.lock().await.write_all(line.as_bytes()).await;
}

pub async fn run(listener: UnixListener, ctx: Arc<Ctx>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let (read, write) = stream.into_split();
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
                warn!("agent socket accept failed: {e}");
            }
        }
    }
}

async fn handle_submit(w: &Writer, ctx: &Arc<Ctx>, request: GateRequest, execute: bool) {
    let digest = match request.digest() {
        Ok(d) => d,
        Err(e) => {
            send(w, &DaemonMsg::Error { message: e.to_string() }).await;
            return;
        }
    };
    let summary = request.summary();
    let (mut tier, mut rule) = ctx.policy.resolve(&request);

    // Session grants can lift ask tiers to allow, never a deny.
    if matches!(tier, Tier::Ask | Tier::AskStrong) {
        if let Operation::Exec { argv, .. } = &request.op {
            if ctx.state.grant_matches(&argv.join(" ")) {
                tier = Tier::Allow;
                rule = "session grant".into();
            }
        }
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
            let short = &digest[..8];
            if tier == Tier::AskStrong && ctx.passkeys_enrolled() {
                if let Some(url) = ctx.approval_url() {
                    warn!("APPROVAL NEEDED [{short}] {summary} — passkey required: {url}");
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

            if let Some(envelope) = approval {
                let via = format!("{:?}:{}", envelope.scheme, envelope.key_id);
                info!("approved [{short}] {summary} via {via}");
                ctx.audit(&digest, &summary, tier, "approved", &via);
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
    let code = child
        .wait()
        .await
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(-1);
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
    #[cfg(not(target_os = "macos"))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

fn new_nonce() -> String {
    // Unique per pending approval; uniqueness matters, unpredictability will
    // matter once envelopes are signed by external devices (phase 2+), at
    // which point this moves to a CSPRNG.
    format!(
        "{}-{}",
        now_unix(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    )
}
