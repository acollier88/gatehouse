//! Phone/relay WebAuthn ceremonies.
//!
//! Same approval release path as the localhost page, but the relying-party
//! id/origin come from relay config so a phone authenticator (Face ID, etc.)
//! can enroll. Passkeys live in `passkeys-phone.json` separately from the
//! localhost set — WebAuthn credentials are RP-bound.
//!
//! The relay is untrusted transport: the ceremony challenge is derived from
//! the request (see [`crate::binding`]) and re-derived at release, so a relay
//! that shows request A while starting a ceremony for request B produces an
//! assertion that fails closed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gatehouse_proto::{paths, ApprovalEnvelope, RelayConfig, SigScheme};
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::audit::now_unix;
use crate::binding;
use crate::Ctx;

pub struct PhoneAuth {
    webauthn: Webauthn,
    reg_states: Mutex<HashMap<Uuid, PasskeyRegistration>>,
    auth_states: Mutex<HashMap<Uuid, (String, PasskeyAuthentication)>>,
}

impl PhoneAuth {
    pub fn new(cfg: &RelayConfig) -> anyhow::Result<Self> {
        let origin = Url::parse(&cfg.origin)?;
        let webauthn = WebauthnBuilder::new(&cfg.rp_id, &origin)?
            .rp_name("Gatehouse")
            .build()?;
        Ok(Self {
            webauthn,
            reg_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
        })
    }
}

pub fn load_phone_passkeys() -> Vec<Passkey> {
    std::fs::read_to_string(paths::phone_passkeys_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

pub fn save_phone_passkeys(keys: &[Passkey]) {
    use std::os::unix::fs::PermissionsExt;
    let path = paths::phone_passkeys_path();
    let write = || -> anyhow::Result<()> {
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, serde_json::to_string_pretty(keys)?)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    };
    if let Err(e) = write() {
        warn!("failed to persist phone passkeys: {e}");
    }
}

pub fn pending_json(ctx: &Ctx) -> serde_json::Value {
    let entries = ctx.state.pending_snapshot();
    let enrolled = ctx.phone_passkeys.lock().unwrap().len();
    serde_json::json!({ "entries": entries, "enrolled": enrolled })
}

pub fn register_start(
    phone: &PhoneAuth,
    ctx: &Ctx,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // Enrolling mints a new approver, so the phone token alone is not enough:
    // the operator must read a one-time code off their own terminal.
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    if !ctx.enroll_codes.redeem(code) {
        warn!("phone enrollment refused: bad or expired enrollment code");
        return Err("enrollment code invalid or expired (run `gate enroll-code`)".into());
    }
    let exclude: Vec<CredentialID> = ctx
        .phone_passkeys
        .lock()
        .unwrap()
        .iter()
        .map(|p| p.cred_id().clone())
        .collect();
    let user_id = Uuid::new_v4();
    let (ccr, state) = phone
        .webauthn
        .start_passkey_registration(user_id, "phone-operator", "Gatehouse Phone", Some(exclude))
        .map_err(|e| format!("register start: {e}"))?;
    phone.reg_states.lock().unwrap().insert(user_id, state);
    Ok(serde_json::json!({ "id": user_id, "options": ccr }))
}

#[derive(Deserialize)]
struct RegFinishBody {
    id: Uuid,
    cred: RegisterPublicKeyCredential,
}

pub fn register_finish(
    phone: &PhoneAuth,
    ctx: &Ctx,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body: RegFinishBody =
        serde_json::from_value(body).map_err(|e| format!("bad body: {e}"))?;
    let state = phone
        .reg_states
        .lock()
        .unwrap()
        .remove(&body.id)
        .ok_or_else(|| "unknown registration ceremony".to_string())?;
    let passkey = phone
        .webauthn
        .finish_passkey_registration(&body.cred, &state)
        .map_err(|e| format!("register finish: {e}"))?;
    let count = {
        let mut keys = ctx.phone_passkeys.lock().unwrap();
        keys.push(passkey);
        save_phone_passkeys(&keys);
        keys.len()
    };
    info!("phone passkey enrolled ({count} total)");
    Ok(serde_json::json!({ "enrolled": count }))
}

pub fn approve_start(
    phone: &PhoneAuth,
    ctx: &Ctx,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let digest = body
        .get("digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing digest".to_string())?
        .to_string();
    let Some(nonce) = ctx.state.pending_nonce(&digest) else {
        return Err("no such pending request".into());
    };
    let creds = ctx.phone_passkeys.lock().unwrap().clone();
    if creds.is_empty() {
        return Err("no phone passkeys enrolled".into());
    }
    let (mut rcr, state) = phone
        .webauthn
        .start_passkey_authentication(&creds)
        .map_err(|e| format!("auth start: {e}"))?;
    let challenge = binding::derive_challenge(&digest, &nonce);
    let state = binding::bind_challenge(&mut rcr, state, &challenge)?;
    let ceremony = Uuid::new_v4();
    let code = binding::verification_code(&digest);
    phone
        .auth_states
        .lock()
        .unwrap()
        .insert(ceremony, (digest, state));
    // `code` is computed here, from the request the daemon actually bound, so
    // a relay that substitutes a digest gets back the substituted code and the
    // human sees it disagree with the daemon terminal.
    Ok(serde_json::json!({ "id": ceremony, "options": rcr, "code": code }))
}

#[derive(Deserialize)]
struct AuthFinishBody {
    id: Uuid,
    cred: PublicKeyCredential,
}

pub fn approve_finish(
    phone: &PhoneAuth,
    ctx: &Arc<Ctx>,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body: AuthFinishBody =
        serde_json::from_value(body).map_err(|e| format!("bad body: {e}"))?;
    let (digest, state) = phone
        .auth_states
        .lock()
        .unwrap()
        .remove(&body.id)
        .ok_or_else(|| "unknown auth ceremony".to_string())?;
    let result = phone
        .webauthn
        .finish_passkey_authentication(&body.cred, &state)
        .map_err(|e| {
            warn!("phone assertion rejected: {e}");
            format!("assertion rejected: {e}")
        })?;

    // Re-derive from the request about to be released and compare against the
    // challenge the authenticator signed. Fails closed, so the release does
    // not rest on the in-memory ceremony→digest pairing alone.
    let nonce = ctx
        .state
        .pending_nonce(&digest)
        .ok_or_else(|| "no such pending request".to_string())?;
    if let Err(e) = binding::check_bound(&body.cred, &digest, &nonce) {
        warn!("phone assertion not bound to [{}]: {e}", &digest[..8]);
        return Err(e);
    }

    let (digest, pending) = ctx.state.take_pending(&digest)?;
    let now = now_unix();
    let assertion = serde_json::to_string(&body.cred).unwrap_or_default();
    let envelope = ApprovalEnvelope {
        digest: digest.clone(),
        nonce: pending.nonce.clone(),
        issued_at: now,
        expires_at: now + 120,
        key_id: hex::encode(result.cred_id().as_ref()),
        scheme: SigScheme::Webauthn,
        sig: assertion,
    };
    let summary = pending.request.summary();
    if pending.tx.send(Some(envelope)).is_err() {
        return Err("request no longer waiting".into());
    }
    info!("phone-webauthn-approved [{}] {summary}", &digest[..8]);
    Ok(serde_json::json!({ "approved": digest }))
}

pub fn deny(ctx: &Ctx, body: serde_json::Value) -> Result<serde_json::Value, String> {
    let digest = body
        .get("digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing digest".to_string())?;
    let (digest, pending) = ctx.state.take_pending(digest)?;
    let _ = pending.tx.send(None);
    Ok(serde_json::json!({ "denied": digest }))
}

/// Reject forged approvals that skip WebAuthn (used by tests + defense in depth).
pub fn reject_unauthenticated_release(body: &serde_json::Value) -> bool {
    // A well-formed finish body must carry a credential object; bare
    // `{approved: true}` style forgeries from a hostile relay are rejected
    // before they ever touch pending state.
    body.get("cred").is_none() || body.get("id").is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forge_without_assertion_is_detected() {
        assert!(reject_unauthenticated_release(&serde_json::json!({
            "approved": true,
            "digest": "abc"
        })));
        assert!(!reject_unauthenticated_release(&serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "cred": { "id": "x", "type": "public-key" }
        })));
    }
}
