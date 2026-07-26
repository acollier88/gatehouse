//! Localhost approval page: passkey enrollment and WebAuthn-attested
//! approvals for `ask-strong` requests.
//!
//! Binding model: the ceremony challenge is derived from the pending request
//! (see [`crate::binding`]) rather than random, and re-derived at release from
//! the request being released. The page is served by the daemon itself here,
//! so the transport is trusted — but the mechanism is shared with the phone
//! relay path and must behave identically.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use gatehouse_proto::{paths, ApprovalEnvelope, SigScheme};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::audit::now_unix;
use crate::binding;
use crate::Ctx;

/// How the daemon advertises the approval page to `gate`.
#[derive(Serialize, Deserialize, Clone)]
pub struct HttpInfo {
    pub port: u16,
    pub token: String,
}

pub struct WebCtx {
    ctx: Arc<Ctx>,
    webauthn: Webauthn,
    token: String,
    reg_states: Mutex<HashMap<Uuid, PasskeyRegistration>>,
    auth_states: Mutex<HashMap<Uuid, (String, PasskeyAuthentication)>>,
}

pub async fn run(ctx: Arc<Ctx>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let token = new_token();

    let origin = Url::parse(&format!("http://localhost:{port}"))?;
    let webauthn = WebauthnBuilder::new("localhost", &origin)?
        .rp_name("Gatehouse")
        .build()?;

    let info = HttpInfo {
        port,
        token: token.clone(),
    };
    let info_path = paths::http_info_path();
    std::fs::write(&info_path, serde_json::to_string(&info)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&info_path, std::fs::Permissions::from_mode(0o600))?;
    }
    ctx.http.set(info).ok();
    info!("approval page: {}", page_url(port, &token));

    let web = Arc::new(WebCtx {
        ctx,
        webauthn,
        token,
        reg_states: Mutex::new(HashMap::new()),
        auth_states: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(page))
        .route("/api/pending", get(api_pending))
        .route("/api/register/start", post(reg_start))
        .route("/api/register/finish", post(reg_finish))
        .route("/api/approve/start", post(auth_start))
        .route("/api/approve/finish", post(auth_finish))
        .route("/api/deny", post(api_deny))
        .with_state(web);
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn page_url(port: u16, token: &str) -> String {
    format!("http://localhost:{port}/?t={token}")
}

fn new_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Constant-time so the token cannot be recovered a byte at a time, and never
/// skippable: every API route calls this first.
fn authed(web: &WebCtx, headers: &HeaderMap) -> Result<(), StatusCode> {
    let presented = headers
        .get("x-gatehouse-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ok = presented.len() == web.token.len()
        && bool::from(presented.as_bytes().ct_eq(web.token.as_bytes()));
    if ok {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn page() -> Html<&'static str> {
    // The page itself contains no secrets; all API calls require the token,
    // which the JS reads from the URL fragment/query the operator opened.
    Html(include_str!("../assets/approve.html"))
}

async fn api_pending(
    State(web): State<Arc<WebCtx>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&web, &headers)?;
    let entries = web.ctx.state.pending_snapshot();
    let enrolled = web.ctx.passkeys.lock().unwrap().len();
    Ok(Json(serde_json::json!({
        "entries": entries,
        "enrolled": enrolled,
    })))
}

#[derive(Deserialize)]
struct RegFinishBody {
    id: Uuid,
    cred: RegisterPublicKeyCredential,
}

#[derive(Deserialize, Default)]
struct RegStartBody {
    #[serde(default)]
    code: String,
}

async fn reg_start(
    State(web): State<Arc<WebCtx>>,
    headers: HeaderMap,
    body: Option<Json<RegStartBody>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&web, &headers)?;
    // Enrolling mints a new approver; the page token alone is not enough.
    let code = body.map(|Json(b)| b.code).unwrap_or_default();
    if !web.ctx.enroll_codes.redeem(&code) {
        warn!("enrollment refused: bad or expired enrollment code");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let exclude: Vec<CredentialID> = web
        .ctx
        .passkeys
        .lock()
        .unwrap()
        .iter()
        .map(|p| p.cred_id().clone())
        .collect();
    let user_id = Uuid::new_v4();
    let (ccr, state) = web
        .webauthn
        .start_passkey_registration(user_id, "operator", "Gatehouse Operator", Some(exclude))
        .map_err(|e| {
            warn!("register start failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    web.reg_states.lock().unwrap().insert(user_id, state);
    Ok(Json(serde_json::json!({ "id": user_id, "options": ccr })))
}

async fn reg_finish(
    State(web): State<Arc<WebCtx>>,
    headers: HeaderMap,
    Json(body): Json<RegFinishBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&web, &headers)?;
    let state = web
        .reg_states
        .lock()
        .unwrap()
        .remove(&body.id)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let passkey = web
        .webauthn
        .finish_passkey_registration(&body.cred, &state)
        .map_err(|e| {
            warn!("register finish failed: {e}");
            StatusCode::BAD_REQUEST
        })?;
    let count = {
        let mut keys = web.ctx.passkeys.lock().unwrap();
        keys.push(passkey);
        crate::save_passkeys(&keys);
        keys.len()
    };
    info!("passkey enrolled ({count} total)");
    Ok(Json(serde_json::json!({ "enrolled": count })))
}

#[derive(Deserialize)]
struct DigestBody {
    digest: String,
}

#[derive(Deserialize)]
struct AuthFinishBody {
    id: Uuid,
    cred: PublicKeyCredential,
}

async fn auth_start(
    State(web): State<Arc<WebCtx>>,
    headers: HeaderMap,
    Json(body): Json<DigestBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&web, &headers)?;
    let Some(nonce) = web.ctx.state.pending_nonce(&body.digest) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let creds = web.ctx.passkeys.lock().unwrap().clone();
    if creds.is_empty() {
        return Err(StatusCode::PRECONDITION_FAILED);
    }
    let (mut rcr, state) = web
        .webauthn
        .start_passkey_authentication(&creds)
        .map_err(|e| {
            warn!("auth start failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let challenge = binding::derive_challenge(&body.digest, &nonce);
    let state = binding::bind_challenge(&mut rcr, state, &challenge).map_err(|e| {
        warn!("challenge binding failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let ceremony = Uuid::new_v4();
    let code = binding::verification_code(&body.digest);
    web.auth_states
        .lock()
        .unwrap()
        .insert(ceremony, (body.digest, state));
    Ok(Json(
        serde_json::json!({ "id": ceremony, "options": rcr, "code": code }),
    ))
}

async fn auth_finish(
    State(web): State<Arc<WebCtx>>,
    headers: HeaderMap,
    Json(body): Json<AuthFinishBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&web, &headers)?;
    let (digest, state) = web
        .auth_states
        .lock()
        .unwrap()
        .remove(&body.id)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let result = web
        .webauthn
        .finish_passkey_authentication(&body.cred, &state)
        .map_err(|e| {
            warn!("assertion rejected: {e}");
            StatusCode::UNAUTHORIZED
        })?;

    // Re-derive from the request about to be released; fail closed on
    // mismatch rather than trusting the in-memory ceremony→digest pairing.
    let nonce = web
        .ctx
        .state
        .pending_nonce(&digest)
        .ok_or(StatusCode::NOT_FOUND)?;
    if let Err(e) = binding::check_bound(&body.cred, &digest, &nonce) {
        warn!("assertion not bound to [{}]: {e}", &digest[..8]);
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (digest, pending) = web
        .ctx
        .state
        .take_pending(&digest)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let now = now_unix();
    let envelope = ApprovalEnvelope {
        digest: digest.clone(),
        nonce: pending.nonce.clone(),
        issued_at: now,
        expires_at: now + 120,
        key_id: hex::encode(result.cred_id().as_ref()),
        scheme: SigScheme::Webauthn,
        // The assertion was verified above by webauthn-rs against the
        // enrolled credential; the envelope records provenance for release
        // and audit. Phase 4 stores the raw assertion here for offline
        // verification.
        sig: String::new(),
    };
    let summary = pending.request.summary();
    if pending.tx.send(Some(envelope)).is_err() {
        return Err(StatusCode::GONE);
    }
    info!("webauthn-approved [{}] {summary}", &digest[..8]);
    Ok(Json(serde_json::json!({ "approved": digest })))
}

async fn api_deny(
    State(web): State<Arc<WebCtx>>,
    headers: HeaderMap,
    Json(body): Json<DigestBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authed(&web, &headers)?;
    let (digest, pending) = web
        .ctx
        .state
        .take_pending(&body.digest)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let _ = pending.tx.send(None);
    Ok(Json(serde_json::json!({ "denied": digest })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_accepts_plain_http_localhost() {
        let origin = Url::parse("http://localhost:4278").unwrap();
        WebauthnBuilder::new("localhost", &origin)
            .expect("localhost origin accepted")
            .rp_name("Gatehouse")
            .build()
            .expect("webauthn builds for http://localhost");
    }
}
