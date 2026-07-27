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

/// One dispatch for both transports: hosted/token traffic gets exactly the
/// enrollment-code and challenge-binding checks the mTLS path gets, because
/// there is no second code path to forget them in.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use gatehouse_proto::{GateRequest, Operation, RelayConfig, Tier};
    use webauthn_rs::prelude::Passkey;

    use crate::state::{Pending, Shared};

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A credential record shaped like one webauthn-rs would have stored. Only
    /// its presence matters here: `approve_start` refuses to begin a ceremony
    /// with no enrolled phone passkey.
    fn synthetic_passkey() -> Passkey {
        serde_json::from_value(serde_json::json!({
            "cred": {
                "cred_id": b64(&[1u8; 16]),
                "cred": {
                    "type_": "ES256",
                    "key": { "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": b64(&[2u8; 32]),
                        "y": b64(&[3u8; 32]),
                    }},
                },
                "counter": 0,
                "transports": null,
                "user_verified": true,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {},
                "attestation": { "data": "None", "metadata": "None" },
                "attestation_format": "none",
            }
        }))
        .expect("passkey shape")
    }

    fn relay_config() -> RelayConfig {
        RelayConfig {
            rp_id: "localhost".into(),
            origin: "https://localhost:8787".into(),
            phone_token: "t".into(),
            listen: String::new(),
            daemon_listen: String::new(),
            transport: Some("hosted".into()),
            daemon_auth: Some("token".into()),
        }
    }

    /// Ctx with one pending ask-strong request and one enrolled phone passkey.
    fn ctx_with_pending() -> (Arc<Ctx>, String, String) {
        let dir = std::env::temp_dir().join(format!("gatehouse-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = Arc::new(Ctx {
            policy: toml::from_str(crate::policy::DEFAULT_POLICY).unwrap(),
            state: Shared::default(),
            approval_timeout: Duration::from_secs(30),
            passkeys: Mutex::new(vec![]),
            phone_passkeys: Mutex::new(vec![synthetic_passkey()]),
            http: OnceLock::new(),
            phone_url: OnceLock::new(),
            enroll_codes: crate::enroll::EnrollCodes::default(),
            auto_open: false,
            audit: Mutex::new(crate::audit::Audit::open(&dir.join("audit.jsonl")).unwrap()),
        });

        let request = GateRequest {
            harness: "test".into(),
            session_id: "s1".into(),
            env_allowlist: vec![],
            op: Operation::Exec {
                argv: vec!["git".into(), "push".into()],
                cwd: "/tmp".into(),
            },
        };
        let digest = request.digest().unwrap();
        let nonce = "nonce-for-test".to_string();
        let (tx, _rx) = tokio::sync::oneshot::channel();
        ctx.state.pending.lock().unwrap().insert(
            digest.clone(),
            Pending {
                request,
                tier: Tier::AskStrong,
                nonce: nonce.clone(),
                submitted: Instant::now(),
                tx,
            },
        );
        (ctx, digest, nonce)
    }

    /// The hosted path must return the daemon-computed verification code, and
    /// the challenge it hands the phone must be the one derived from the
    /// request — otherwise hosted mode would quietly lose PR #5's binding.
    #[test]
    fn approve_start_over_the_hosted_dispatch_is_bound_and_carries_the_code() {
        let (ctx, digest, nonce) = ctx_with_pending();
        let phone = PhoneAuth::new(&relay_config()).unwrap();
        let out = dispatch(
            &ctx,
            &phone,
            RelayMethod::ApproveStart,
            serde_json::json!({ "digest": digest }),
        )
        .expect("approve start");

        assert_eq!(out["code"], serde_json::json!(&digest[..8]));
        let expected = crate::binding::derive_challenge(&digest, &nonce);
        assert_eq!(
            out["options"]["publicKey"]["challenge"],
            serde_json::json!(b64(&expected)),
        );
    }

    /// Enrollment gating is not bypassed by going through the relay dispatch.
    #[test]
    fn register_start_over_the_hosted_dispatch_still_needs_a_code() {
        let (ctx, _digest, _nonce) = ctx_with_pending();
        let phone = PhoneAuth::new(&relay_config()).unwrap();
        assert!(dispatch(&ctx, &phone, RelayMethod::RegisterStart, serde_json::json!({})).is_err());
        assert!(dispatch(
            &ctx,
            &phone,
            RelayMethod::RegisterStart,
            serde_json::json!({ "code": "AAAAAAAA" })
        )
        .is_err());
        let code = ctx.enroll_codes.issue();
        assert!(dispatch(
            &ctx,
            &phone,
            RelayMethod::RegisterStart,
            serde_json::json!({ "code": code })
        )
        .is_ok());
    }

    /// A finish body with no assertion never reaches pending state.
    #[test]
    fn approve_finish_over_the_hosted_dispatch_rejects_a_bodyless_forge() {
        let (ctx, digest, _nonce) = ctx_with_pending();
        let phone = PhoneAuth::new(&relay_config()).unwrap();
        let err = dispatch(
            &ctx,
            &phone,
            RelayMethod::ApproveFinish,
            serde_json::json!({ "approved": true, "digest": digest.clone() }),
        )
        .expect_err("bodyless finish must fail");
        assert!(err.contains("forged approval"));
        assert!(ctx.state.pending.lock().unwrap().contains_key(&digest));
    }
}
