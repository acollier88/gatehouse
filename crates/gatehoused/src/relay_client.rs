//! Daemon-side dial-out to the phone approval relay over mTLS WebSocket.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use gatehouse_proto::{DaemonToRelay, RelayMethod, RelayToDaemon};
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

use crate::certs::RelayMaterial;
use crate::phone::{self, PhoneAuth};
use crate::Ctx;

pub async fn run(ctx: Arc<Ctx>, relay_url: &str) -> anyhow::Result<()> {
    let material = RelayMaterial::load()?;
    let phone = Arc::new(PhoneAuth::new(&material.config)?);
    // Prefer the phone console URL for ask-strong prompts when relay is used.
    let _ = ctx.phone_url.set(material.phone_url());

    let mut ws_url = relay_url.trim_end_matches('/').to_string();
    if !ws_url.ends_with("/ws") {
        ws_url.push_str("/ws");
    }
    // https → wss, http → ws
    if let Some(rest) = ws_url.strip_prefix("https://") {
        ws_url = format!("wss://{rest}");
    } else if let Some(rest) = ws_url.strip_prefix("http://") {
        ws_url = format!("ws://{rest}");
    }

    let tls = material.daemon_client_config()?;
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls));

    info!("connecting to relay {ws_url}");
    loop {
        match connect_once(ctx.clone(), phone.clone(), &ws_url, connector.clone()).await {
            Ok(()) => warn!("relay session ended; reconnecting in 2s"),
            Err(e) => warn!("relay connect failed: {e}; retrying in 2s"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn connect_once(
    ctx: Arc<Ctx>,
    phone: Arc<PhoneAuth>,
    ws_url: &str,
    connector: tokio_tungstenite::Connector,
) -> anyhow::Result<()> {
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
        ws_url,
        None,
        false,
        Some(connector),
    )
    .await?;
    let (mut sink, mut stream) = ws.split();

    let enrolled = ctx.phone_passkeys.lock().unwrap().len();
    let hello = serde_json::to_string(&DaemonToRelay::Hello { enrolled })?;
    sink.send(Message::Text(hello.into())).await?;
    info!("relay connected");

    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let Message::Text(text) = msg else { continue };
        let req: RelayToDaemon = match serde_json::from_str(&text) {
            Ok(r) => r,
            Err(e) => {
                warn!("bad relay rpc: {e}");
                continue;
            }
        };
        let RelayToDaemon::Rpc { id, method, body } = req;
        let reply = dispatch(&ctx, &phone, method, body);
        let out = match reply {
            Ok(body) => DaemonToRelay::RpcOk { id, body },
            Err(message) => DaemonToRelay::RpcErr { id, message },
        };
        sink.send(Message::Text(serde_json::to_string(&out)?.into()))
            .await?;
    }
    Ok(())
}

fn dispatch(
    ctx: &Arc<Ctx>,
    phone: &PhoneAuth,
    method: RelayMethod,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    match method {
        RelayMethod::Pending => Ok(phone::pending_json(ctx)),
        RelayMethod::RegisterStart => phone::register_start(phone, ctx, body),
        RelayMethod::RegisterFinish => phone::register_finish(phone, ctx, body),
        RelayMethod::ApproveStart => phone::approve_start(phone, ctx, body),
        RelayMethod::ApproveFinish => {
            if phone::reject_unauthenticated_release(&body) {
                return Err("forged approval: missing WebAuthn assertion".into());
            }
            phone::approve_finish(phone, ctx, body)
        }
        RelayMethod::Deny => phone::deny(ctx, body),
    }
}
