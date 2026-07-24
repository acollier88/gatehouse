//! Operator control socket: pending list, approve/deny, grants, status.

use std::sync::Arc;
use std::time::{Duration, Instant};

use gatehouse_proto::{ApprovalEnvelope, CtlMsg, CtlResp, SigScheme};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::warn;

use crate::audit::now_unix;
use crate::Ctx;

/// Operator approvals are valid this long once issued; generous because the
/// waiting submit task consumes them immediately.
const OPERATOR_ENVELOPE_TTL_SECS: i64 = 120;

pub async fn run(listener: UnixListener, ctx: Arc<Ctx>, started: Instant) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut lines = BufReader::new(read).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let resp = match serde_json::from_str::<CtlMsg>(&line) {
                            Ok(msg) => handle(&ctx, msg, started),
                            Err(e) => CtlResp::Error {
                                message: format!("bad message: {e}"),
                            },
                        };
                        let mut out = serde_json::to_string(&resp).expect("serializable");
                        out.push('\n');
                        if write.write_all(out.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
            Err(e) => warn!("ctl socket accept failed: {e}"),
        }
    }
}

fn handle(ctx: &Arc<Ctx>, msg: CtlMsg, started: Instant) -> CtlResp {
    match msg {
        CtlMsg::Pending => CtlResp::Pending {
            entries: ctx.state.pending_snapshot(),
        },
        CtlMsg::Approve { digest_prefix } => decide(ctx, &digest_prefix, true),
        CtlMsg::Deny { digest_prefix } => decide(ctx, &digest_prefix, false),
        CtlMsg::Grant { argv_glob, ttl_secs } => {
            ctx.state
                .add_grant(argv_glob.clone(), Duration::from_secs(ttl_secs));
            CtlResp::Ok {
                message: format!("granted `{argv_glob}` for {ttl_secs}s"),
            }
        }
        CtlMsg::Status => CtlResp::Status {
            version: gatehouse_proto::wire::PROTOCOL_VERSION,
            pending: ctx.state.pending.lock().unwrap().len(),
            grants: ctx.state.grant_snapshot(),
            uptime_secs: started.elapsed().as_secs(),
        },
    }
}

fn decide(ctx: &Arc<Ctx>, digest_prefix: &str, approve: bool) -> CtlResp {
    match ctx.state.take_pending(digest_prefix) {
        Ok((digest, pending)) => {
            let summary = pending.request.summary();
            let verdict = if approve {
                let now = now_unix();
                // Phase 1: unattested operator approval. Still envelope-bound
                // so the release path verifies digest + nonce + expiry the
                // same way signed approvals will.
                Some(ApprovalEnvelope {
                    digest: digest.clone(),
                    nonce: pending.nonce.clone(),
                    issued_at: now,
                    expires_at: now + OPERATOR_ENVELOPE_TTL_SECS,
                    key_id: "operator-ctl".into(),
                    scheme: SigScheme::None,
                    sig: String::new(),
                })
            } else {
                None
            };
            if pending.tx.send(verdict).is_err() {
                return CtlResp::Error {
                    message: "requester is gone (timed out or disconnected)".into(),
                };
            }
            CtlResp::Ok {
                message: format!(
                    "{} [{}] {summary}",
                    if approve { "approved" } else { "denied" },
                    &digest[..8]
                ),
            }
        }
        Err(e) => CtlResp::Error { message: e },
    }
}
