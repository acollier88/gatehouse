//! Phone-facing approval relay.
//!
//! Two TLS listeners share state:
//! - **Phone** (`--listen`): server-auth TLS, serves the PWA, requires the
//!   phone bearer token. Forwards API calls to the connected daemon.
//! - **Daemon** (`--daemon-listen`): mTLS (client cert required). One
//!   WebSocket at a time carries RPCs; ceremonies stay on the daemon.
//!
//! Trust: the relay is transport. It cannot manufacture an approval — release
//! needs an assertion the daemon verifies against an enrolled passkey — and it
//! can no longer redirect a real approval onto another request, because the
//! ceremony challenge is derived from the request digest and re-derived at
//! release (`crate::binding`). What a relay *can* still do is serve malicious
//! PWA JavaScript: it controls the page, so it can lie about what the gesture
//! is for. The verification code shown next to the approve button is the
//! human's out-of-band check against the daemon terminal; a pinned native
//! client is the full fix. See docs/threat-model.md.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use gatehouse_proto::{DaemonToRelay, RelayMethod, RelayToDaemon};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

use crate::certs::RelayMaterial;

struct PendingRpc {
    tx: oneshot::Sender<Result<serde_json::Value, String>>,
}

struct DaemonLink {
    outbound: mpsc::UnboundedSender<String>,
    rpcs: HashMap<String, PendingRpc>,
}

struct RelayState {
    material: RelayMaterial,
    daemon: Mutex<Option<DaemonLink>>,
}

pub async fn run(listen: SocketAddr, daemon_listen: SocketAddr) -> anyhow::Result<()> {
    let material = RelayMaterial::load()?;
    info!("relay phone URL: {}", material.phone_url());
    info!("rp_id={} origin={}", material.config.rp_id, material.config.origin);

    let state = Arc::new(RelayState {
        material,
        daemon: Mutex::new(None),
    });

    let phone_app = Router::new()
        .route("/", get(page))
        .route("/manifest.webmanifest", get(manifest))
        .route("/sw.js", get(service_worker))
        .route("/api/pending", get(api_pending))
        .route("/api/register/start", post(api_register_start))
        .route("/api/register/finish", post(api_register_finish))
        .route("/api/approve/start", post(api_approve_start))
        .route("/api/approve/finish", post(api_approve_finish))
        .route("/api/deny", post(api_deny))
        .with_state(state.clone());

    let daemon_app = Router::new()
        .route("/ws", get(daemon_ws))
        .with_state(state.clone());

    let phone_tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
        state.material.relay_server_config()?,
    ));
    let daemon_tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
        state.material.daemon_server_config()?,
    ));

    info!("phone HTTPS listening on {listen}");
    info!("daemon mTLS listening on {daemon_listen}");

    tokio::select! {
        r = axum_server::bind_rustls(listen, phone_tls).serve(phone_app.into_make_service()) => r?,
        r = axum_server::bind_rustls(daemon_listen, daemon_tls).serve(daemon_app.into_make_service()) => r?,
        _ = tokio::signal::ctrl_c() => {
            info!("relay shutting down");
        }
    }
    Ok(())
}

async fn page() -> Html<&'static str> {
    Html(include_str!("../assets/approve.html"))
}

async fn manifest() -> ([(&'static str, &'static str); 1], &'static str) {
    (
        [("content-type", "application/manifest+json")],
        r##"{"name":"Gatehouse","short_name":"Gatehouse","start_url":"/","display":"standalone","background_color":"#111","theme_color":"#111"}"##,
    )
}

async fn service_worker() -> ([(&'static str, &'static str); 1], &'static str) {
    // Installable shell + page-driven notifications. Approval crypto still
    // goes through the page → relay → daemon path; the SW only surfaces UX.
    (
        [("content-type", "application/javascript")],
        r##"
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(clients.claim()));
let last = '';
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'pending' && e.data.digest && e.data.digest !== last) {
    last = e.data.digest;
    self.registration.showNotification('Gatehouse approval needed', {
      body: e.data.summary || 'Open Gatehouse to approve',
      data: e.data,
    });
  }
});
"##,
    )
}

/// Constant-time: the phone token is a bearer secret on a public listener.
fn authed(state: &RelayState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let presented = headers
        .get("x-gatehouse-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = state.material.config.phone_token.as_bytes();
    let ok = presented.len() == expected.len()
        && bool::from(presented.as_bytes().ct_eq(expected));
    if ok {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn rpc(
    state: &RelayState,
    method: RelayMethod,
    body: serde_json::Value,
) -> Result<serde_json::Value, StatusCode> {
    let id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    let msg = RelayToDaemon::Rpc {
        id: id.clone(),
        method,
        body,
    };
    let line = serde_json::to_string(&msg).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    {
        let mut guard = state.daemon.lock().await;
        let Some(link) = guard.as_mut() else {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        };
        link.rpcs.insert(id.clone(), PendingRpc { tx });
        if link.outbound.send(line).is_err() {
            link.rpcs.remove(&id);
            *guard = None;
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(_))) => Err(StatusCode::BAD_REQUEST),
        Ok(Err(_)) => Err(StatusCode::BAD_GATEWAY),
        Err(_) => {
            let mut guard = state.daemon.lock().await;
            if let Some(link) = guard.as_mut() {
                link.rpcs.remove(&id);
            }
            Err(StatusCode::GATEWAY_TIMEOUT)
        }
    }
}

async fn api_pending(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&state, &headers)?;
    Ok(Json(rpc(&state, RelayMethod::Pending, serde_json::json!({})).await?))
}

async fn api_register_start(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&state, &headers)?;
    Ok(Json(
        rpc(&state, RelayMethod::RegisterStart, serde_json::json!({})).await?,
    ))
}

async fn api_register_finish(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&state, &headers)?;
    Ok(Json(rpc(&state, RelayMethod::RegisterFinish, body).await?))
}

async fn api_approve_start(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&state, &headers)?;
    Ok(Json(rpc(&state, RelayMethod::ApproveStart, body).await?))
}

async fn api_approve_finish(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&state, &headers)?;
    // Defense in depth: refuse bare forgeries before they reach the daemon.
    if crate::phone::reject_unauthenticated_release(&body) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    match rpc(&state, RelayMethod::ApproveFinish, body).await {
        Ok(v) => Ok(Json(v)),
        Err(StatusCode::BAD_REQUEST) => Err(StatusCode::UNAUTHORIZED),
        Err(e) => Err(e),
    }
}

async fn api_deny(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&state, &headers)?;
    Ok(Json(rpc(&state, RelayMethod::Deny, body).await?))
}

async fn daemon_ws(
    State(state): State<Arc<RelayState>>,
    ws: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| handle_daemon(state, socket))
}

async fn handle_daemon(state: Arc<RelayState>, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    {
        let mut guard = state.daemon.lock().await;
        if guard.is_some() {
            warn!("rejecting second daemon connection");
            let _ = sink
                .send(Message::Text(
                    "{\"type\":\"rpc_err\",\"id\":\"\",\"message\":\"daemon already connected\"}"
                        .into(),
                ))
                .await;
            return;
        }
        *guard = Some(DaemonLink {
            outbound: tx,
            rpcs: HashMap::new(),
        });
    }
    info!("daemon connected over mTLS");

    let write = async {
        while let Some(line) = rx.recv().await {
            if sink.send(Message::Text(line.into())).await.is_err() {
                break;
            }
        }
    };

    let read = async {
        while let Some(Ok(msg)) = stream.next().await {
            let Message::Text(text) = msg else { continue };
            match serde_json::from_str::<DaemonToRelay>(&text) {
                Ok(DaemonToRelay::Hello { enrolled }) => {
                    info!("daemon hello; phone passkeys enrolled: {enrolled}");
                }
                Ok(DaemonToRelay::RpcOk { id, body }) => {
                    let mut guard = state.daemon.lock().await;
                    if let Some(link) = guard.as_mut() {
                        if let Some(PendingRpc { tx }) = link.rpcs.remove(&id) {
                            let _ = tx.send(Ok(body));
                        }
                    }
                }
                Ok(DaemonToRelay::RpcErr { id, message }) => {
                    let mut guard = state.daemon.lock().await;
                    if let Some(link) = guard.as_mut() {
                        if let Some(PendingRpc { tx }) = link.rpcs.remove(&id) {
                            let _ = tx.send(Err(message));
                        }
                    }
                }
                Err(e) => warn!("bad daemon message: {e}"),
            }
        }
    };

    tokio::select! {
        _ = write => {}
        _ = read => {}
    }

    let mut guard = state.daemon.lock().await;
    if let Some(link) = guard.take() {
        for (_, PendingRpc { tx }) in link.rpcs {
            let _ = tx.send(Err("daemon disconnected".into()));
        }
    }
    warn!("daemon disconnected");
}
