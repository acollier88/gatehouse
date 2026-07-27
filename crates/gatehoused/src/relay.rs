//! Phone-facing approval relay.
//!
//! Two listeners share state:
//! - **Phone** (`--listen`): server-auth TLS, serves the PWA, requires the
//!   phone bearer token. Forwards API calls to the connected daemon(s).
//! - **Daemon** (`--daemon-listen`): mTLS (client cert required) and/or
//!   token-auth WebSocket on the phone port at `/ws`. Hosted mode maps
//!   `device_id → DaemonLink` so enrolled brokers stay isolated.
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
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use gatehouse_proto::{DaemonToRelay, RelayMethod, RelayToDaemon};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

use crate::certs::RelayMaterial;
use crate::devices;

struct PendingRpc {
    tx: oneshot::Sender<Result<serde_json::Value, String>>,
}

struct DaemonLink {
    outbound: mpsc::UnboundedSender<String>,
    rpcs: HashMap<String, PendingRpc>,
}

struct RelayState {
    material: RelayMaterial,
    /// Connected brokers keyed by device_id (`_mtls` for legacy single dial).
    daemons: Mutex<HashMap<String, DaemonLink>>,
}

pub async fn run(listen: SocketAddr, daemon_listen: SocketAddr) -> anyhow::Result<()> {
    let material = RelayMaterial::load()?;
    info!("relay phone URL: {}", material.phone_url());
    info!("rp_id={} origin={}", material.config.rp_id, material.config.origin);
    info!("daemon_auth={}", material.daemon_auth());

    let state = Arc::new(RelayState {
        material,
        daemons: Mutex::new(HashMap::new()),
    });

    let auth = state.material.daemon_auth().to_string();
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
        .route("/ws", get(daemon_ws_token))
        .with_state(state.clone());

    let phone_tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
        state.material.relay_server_config()?,
    ));

    info!("phone HTTPS listening on {listen}");

    let mtls = auth == "mtls" || auth == "both";
    if mtls {
        let daemon_app = Router::new()
            .route("/ws", get(daemon_ws_mtls))
            .with_state(state.clone());
        let daemon_tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
            state.material.daemon_server_config()?,
        ));
        info!("daemon mTLS listening on {daemon_listen}");
        tokio::select! {
            r = axum_server::bind_rustls(listen, phone_tls).serve(phone_app.into_make_service()) => r?,
            r = axum_server::bind_rustls(daemon_listen, daemon_tls).serve(daemon_app.into_make_service()) => r?,
            _ = tokio::signal::ctrl_c() => {
                info!("relay shutting down");
            }
        }
    } else {
        info!("daemon token WS on phone port /ws (no mTLS listener)");
        tokio::select! {
            r = axum_server::bind_rustls(listen, phone_tls).serve(phone_app.into_make_service()) => r?,
            _ = tokio::signal::ctrl_c() => {
                info!("relay shutting down");
            }
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

fn device_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-gatehouse-device")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[derive(Deserialize)]
struct DeviceQuery {
    d: Option<String>,
}

/// Authorize a phone call and return the device it may address.
///
/// The presented bearer *is* the device selector — `?d=` / `X-Gatehouse-Device`
/// only cross-check it — so device A's phone token can never reach device B.
/// Comparisons are constant-time over every enrolled record.
fn phone_device(
    state: &RelayState,
    headers: &HeaderMap,
    query: &DeviceQuery,
) -> Result<String, StatusCode> {
    let presented = headers
        .get("x-gatehouse-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let requested = query
        .d
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| device_from_headers(headers));
    let enrolled = devices::load_devices().map_err(|e| {
        warn!("device store unreadable: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    match devices::authorize_phone(
        &enrolled,
        &state.material.config.phone_token,
        presented,
        requested.as_deref(),
    ) {
        devices::Authz::Device(id) => Ok(id),
        devices::Authz::LegacyMtls => Ok(devices::MTLS_DEVICE.to_string()),
        devices::Authz::WrongDevice => {
            warn!("phone token addressed a device it does not own");
            Err(StatusCode::FORBIDDEN)
        }
        devices::Authz::Unauthenticated => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn rpc(
    state: &RelayState,
    device_id: &str,
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
        let mut guard = state.daemons.lock().await;
        let Some(link) = guard.get_mut(device_id) else {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        };
        link.rpcs.insert(id.clone(), PendingRpc { tx });
        if link.outbound.send(line).is_err() {
            link.rpcs.remove(&id);
            guard.remove(device_id);
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(_))) => Err(StatusCode::BAD_REQUEST),
        Ok(Err(_)) => Err(StatusCode::BAD_GATEWAY),
        Err(_) => {
            let mut guard = state.daemons.lock().await;
            if let Some(link) = guard.get_mut(device_id) {
                link.rpcs.remove(&id);
            }
            Err(StatusCode::GATEWAY_TIMEOUT)
        }
    }
}

async fn api_pending(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Query(query): Query<DeviceQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device = phone_device(&state, &headers, &query)?;
    Ok(Json(
        rpc(&state, &device, RelayMethod::Pending, serde_json::json!({})).await?,
    ))
}

async fn api_register_start(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Query(query): Query<DeviceQuery>,
    body: Option<Json<serde_json::Value>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device = phone_device(&state, &headers, &query)?;
    // Carries the one-time enrollment code; the daemon validates it.
    let body = body.map(|Json(v)| v).unwrap_or_else(|| serde_json::json!({}));
    Ok(Json(
        rpc(&state, &device, RelayMethod::RegisterStart, body).await?,
    ))
}

async fn api_register_finish(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Query(query): Query<DeviceQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device = phone_device(&state, &headers, &query)?;
    Ok(Json(
        rpc(&state, &device, RelayMethod::RegisterFinish, body).await?,
    ))
}

async fn api_approve_start(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Query(query): Query<DeviceQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device = phone_device(&state, &headers, &query)?;
    Ok(Json(
        rpc(&state, &device, RelayMethod::ApproveStart, body).await?,
    ))
}

async fn api_approve_finish(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Query(query): Query<DeviceQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device = phone_device(&state, &headers, &query)?;
    if crate::phone::reject_unauthenticated_release(&body) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    match rpc(&state, &device, RelayMethod::ApproveFinish, body).await {
        Ok(v) => Ok(Json(v)),
        Err(StatusCode::BAD_REQUEST) => Err(StatusCode::UNAUTHORIZED),
        Err(e) => Err(e),
    }
}

async fn api_deny(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Query(query): Query<DeviceQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device = phone_device(&state, &headers, &query)?;
    Ok(Json(rpc(&state, &device, RelayMethod::Deny, body).await?))
}

async fn daemon_ws_token(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let auth = state.material.daemon_auth();
    if auth != "token" && auth != "both" {
        return Err(StatusCode::NOT_FOUND);
    }
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let rec = devices::lookup_token(&token)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let device_id = rec.device_id;
    Ok(ws.on_upgrade(move |socket| handle_daemon(state, socket, device_id)))
}

async fn daemon_ws_mtls(
    State(state): State<Arc<RelayState>>,
    ws: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    // An mTLS client cert proves possession of the single shared CA key, not
    // of any device token, so this channel *is* the legacy single-tenant
    // identity — full stop. Multi-device routing requires the token listener.
    ws.on_upgrade(move |socket| handle_daemon(state, socket, devices::MTLS_DEVICE.to_string()))
}

/// Identity is a property of the authenticated channel, never of the Hello.
/// A daemon claiming a different `device_id` is logged and ignored, so an
/// mTLS connection cannot take over an enrolled device's route (and a
/// token connection cannot leave its own).
fn hello_identity(authenticated: &str, claimed: Option<&str>) -> String {
    if let Some(id) = claimed.filter(|id| !id.is_empty() && *id != authenticated) {
        warn!("ignoring hello device_id {id}: channel is authenticated as {authenticated}");
    }
    authenticated.to_string()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("authorization")?.to_str().ok()?;
    let token = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer "))?;
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

async fn handle_daemon(state: Arc<RelayState>, socket: WebSocket, device_id: String) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    {
        let mut guard = state.daemons.lock().await;
        if guard.contains_key(&device_id) {
            warn!("rejecting second connection for device {device_id}");
            let _ = sink
                .send(Message::Text(
                    "{\"type\":\"rpc_err\",\"id\":\"\",\"message\":\"device already connected\"}"
                        .into(),
                ))
                .await;
            return;
        }
        guard.insert(
            device_id.clone(),
            DaemonLink {
                outbound: tx,
                rpcs: HashMap::new(),
            },
        );
    }
    info!("daemon connected as {device_id}");

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
                Ok(DaemonToRelay::Hello {
                    enrolled,
                    device_id: hello_id,
                }) => {
                    let device_id = hello_identity(&device_id, hello_id.as_deref());
                    info!("daemon hello device={device_id}; phone passkeys enrolled: {enrolled}");
                }
                Ok(DaemonToRelay::RpcOk { id, body }) => {
                    let mut guard = state.daemons.lock().await;
                    if let Some(link) = guard.get_mut(&device_id) {
                        if let Some(PendingRpc { tx }) = link.rpcs.remove(&id) {
                            let _ = tx.send(Ok(body));
                        }
                    }
                }
                Ok(DaemonToRelay::RpcErr { id, message }) => {
                    let mut guard = state.daemons.lock().await;
                    if let Some(link) = guard.get_mut(&device_id) {
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

    let mut guard = state.daemons.lock().await;
    if let Some(link) = guard.remove(&device_id) {
        for (_, PendingRpc { tx }) in link.rpcs {
            let _ = tx.send(Err("daemon disconnected".into()));
        }
    }
    warn!("daemon disconnected ({device_id})");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S4: an mTLS connection presents the shared CA client cert, not a device
    /// token, so a Hello claiming an enrolled device_id must not move its route.
    #[test]
    fn hello_cannot_remap_the_mtls_channel() {
        assert_eq!(
            hello_identity(devices::MTLS_DEVICE, Some("dev_victim")),
            devices::MTLS_DEVICE
        );
        assert_eq!(
            hello_identity(devices::MTLS_DEVICE, None),
            devices::MTLS_DEVICE
        );
    }

    #[test]
    fn hello_cannot_move_a_token_channel_either() {
        assert_eq!(hello_identity("dev_aaa", Some("dev_bbb")), "dev_aaa");
        assert_eq!(hello_identity("dev_aaa", Some("dev_aaa")), "dev_aaa");
        assert_eq!(hello_identity("dev_aaa", Some("")), "dev_aaa");
        assert_eq!(hello_identity("dev_aaa", None), "dev_aaa");
    }
}
