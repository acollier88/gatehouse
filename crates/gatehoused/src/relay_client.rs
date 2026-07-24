//! Daemon-side dial-out to the phone approval relay.
//!
//! Personal mode: mTLS WebSocket to the daemon port.
//! Hosted / token mode: server-auth TLS + `Authorization: Bearer <device token>`
//! to the phone port `/ws` (no shared CA file copy required).

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use gatehouse_proto::{paths, DaemonToRelay, DeviceCred, RelayMethod, RelayToDaemon, RelayToml};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

use crate::certs::{self, RelayMaterial};
use crate::phone::{self, PhoneAuth};
use crate::Ctx;

pub enum DialConfig {
    Mtls { url: String },
    Token { cred: DeviceCred },
}

impl DialConfig {
    /// Resolve dial-out from flags / `device.json` / `relay.toml`.
    pub fn resolve(
        relay_url: Option<String>,
        relay_token: Option<String>,
    ) -> anyhow::Result<Option<Self>> {
        if let (Some(url), Some(token)) = (&relay_url, &relay_token) {
            let (rp_id, origin) = rp_from_url(url)?;
            return Ok(Some(Self::Token {
                cred: DeviceCred {
                    device_id: "cli".into(),
                    token: token.clone(),
                    endpoint: url.trim_end_matches('/').to_string(),
                    rp_id,
                    origin,
                    phone_token: None,
                },
            }));
        }
        if let Some(url) = relay_url {
            return Ok(Some(Self::Mtls { url }));
        }
        if paths::device_cred_path().exists() {
            let mut cred: DeviceCred =
                serde_json::from_str(&std::fs::read_to_string(paths::device_cred_path())?)?;
            if let Ok(toml) = load_relay_toml() {
                if let Some(ep) = toml.endpoint {
                    cred.endpoint = ep;
                }
            }
            return Ok(Some(Self::Token { cred }));
        }
        if let Ok(toml) = load_relay_toml() {
            if let (Some(endpoint), Some(token)) = (toml.endpoint, toml.token) {
                let (rp_id, origin) = rp_from_url(&endpoint)?;
                return Ok(Some(Self::Token {
                    cred: DeviceCred {
                        device_id: toml.device_id.unwrap_or_else(|| "toml".into()),
                        token,
                        endpoint,
                        rp_id,
                        origin,
                        phone_token: None,
                    },
                }));
            }
        }
        Ok(None)
    }
}

fn load_relay_toml() -> anyhow::Result<RelayToml> {
    let path = paths::relay_toml_path();
    let text = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&text)?)
}

fn rp_from_url(url: &str) -> anyhow::Result<(String, String)> {
    let u = url::Url::parse(url)?;
    let host = u
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("relay URL missing host"))?
        .to_string();
    let origin = match u.port() {
        Some(p) => format!("{}://{}:{p}", u.scheme(), host),
        None => format!("{}://{}", u.scheme(), host),
    };
    Ok((host, origin))
}

pub async fn run(ctx: Arc<Ctx>, dial: DialConfig) -> anyhow::Result<()> {
    match dial {
        DialConfig::Mtls { url } => run_mtls(ctx, &url).await,
        DialConfig::Token { cred } => run_token(ctx, cred).await,
    }
}

async fn run_mtls(ctx: Arc<Ctx>, relay_url: &str) -> anyhow::Result<()> {
    let material = RelayMaterial::load()?;
    let phone = Arc::new(PhoneAuth::new(&material.config)?);
    let _ = ctx.phone_url.set(material.phone_url());

    let ws_url = to_ws_url(relay_url);
    let tls = material.daemon_client_config()?;
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls));

    info!("connecting to relay {ws_url} (mTLS)");
    loop_connect(ctx, phone, ws_url, connector, None, None).await
}

async fn run_token(ctx: Arc<Ctx>, cred: DeviceCred) -> anyhow::Result<()> {
    let phone = Arc::new(PhoneAuth::new(&cred.as_relay_config())?);
    if let Some(url) = cred.phone_url() {
        let _ = ctx.phone_url.set(url);
    }

    let ws_url = to_ws_url(&cred.endpoint);
    let tls = match RelayMaterial::load() {
        Ok(m) => m.token_client_config()?,
        Err(_) => certs::public_tls_client()?,
    };
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls));

    info!(
        "connecting to relay {ws_url} (device token, id={})",
        cred.device_id
    );
    loop_connect(
        ctx,
        phone,
        ws_url,
        connector,
        Some(cred.token),
        Some(cred.device_id),
    )
    .await
}

async fn loop_connect(
    ctx: Arc<Ctx>,
    phone: Arc<PhoneAuth>,
    ws_url: String,
    connector: tokio_tungstenite::Connector,
    bearer: Option<String>,
    device_id: Option<String>,
) -> anyhow::Result<()> {
    loop {
        match connect_once(
            ctx.clone(),
            phone.clone(),
            &ws_url,
            connector.clone(),
            bearer.as_deref(),
            device_id.as_deref(),
        )
        .await
        {
            Ok(()) => warn!("relay session ended; reconnecting in 2s"),
            Err(e) => warn!("relay connect failed: {e}; retrying in 2s"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn to_ws_url(relay_url: &str) -> String {
    let mut ws_url = relay_url.trim_end_matches('/').to_string();
    if !ws_url.ends_with("/ws") {
        ws_url.push_str("/ws");
    }
    if let Some(rest) = ws_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = ws_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        ws_url
    }
}

async fn connect_once(
    ctx: Arc<Ctx>,
    phone: Arc<PhoneAuth>,
    ws_url: &str,
    connector: tokio_tungstenite::Connector,
    bearer: Option<&str>,
    device_id: Option<&str>,
) -> anyhow::Result<()> {
    let mut request = ws_url.into_client_request()?;
    if let Some(token) = bearer {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))?;
        request.headers_mut().insert("Authorization", value);
    }

    let (ws, _) =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
            .await?;
    let (mut sink, mut stream) = ws.split();

    let enrolled = ctx.phone_passkeys.lock().unwrap().len();
    let hello = serde_json::to_string(&DaemonToRelay::Hello {
        enrolled,
        device_id: device_id.map(|s| s.to_string()),
    })?;
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
