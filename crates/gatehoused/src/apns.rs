//! APNs device registration and best-effort wake.
//!
//! Tokens are stored encrypted at rest. A SHA-256 hash is kept only for
//! dedupe/logging. Push payloads must never authorize an approval.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use gatehouse_proto::paths;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApnsRecord {
    pub device_id: String,
    pub token_hash: String,
    pub token_ct: String,
    pub nonce: String,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Default)]
struct StoreFile {
    devices: Vec<ApnsRecord>,
}

fn key_bytes() -> anyhow::Result<[u8; 32]> {
    let path = paths::apns_key_path();
    if path.exists() {
        let raw = std::fs::read(&path)?;
        let mut key = [0u8; 32];
        if raw.len() == 32 {
            key.copy_from_slice(&raw);
            return Ok(key);
        }
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, key)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(key)
}

fn encrypt_token(token: &str) -> anyhow::Result<(String, String)> {
    let cipher = Aes256Gcm::new_from_slice(&key_bytes()?)?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), token.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
    Ok((hex::encode(ct), hex::encode(nonce_bytes)))
}

fn decrypt_token(rec: &ApnsRecord) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new_from_slice(&key_bytes()?)?;
    let nonce = hex::decode(&rec.nonce)?;
    let ct = hex::decode(&rec.token_ct)?;
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
    Ok(String::from_utf8(pt)?)
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn load() -> StoreFile {
    std::fs::read_to_string(paths::apns_devices_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(store: &StoreFile) -> anyhow::Result<()> {
    let path = paths::apns_devices_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(store)?)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Register or replace a device token. Returns the hash (never the raw token).
pub fn register(device_id: &str, token: &str) -> anyhow::Result<String> {
    if token.is_empty() || device_id.is_empty() {
        anyhow::bail!("device_id and token required");
    }
    let hash = token_hash(token);
    let (token_ct, nonce) = encrypt_token(token)?;
    let mut store = load();
    store.devices.retain(|d| d.device_id != device_id && d.token_hash != hash);
    store.devices.push(ApnsRecord {
        device_id: device_id.to_string(),
        token_hash: hash.clone(),
        token_ct,
        nonce,
        updated_at: crate::audit::now_unix(),
    });
    save(&store)?;
    Ok(hash)
}

pub fn unregister(device_id: &str) -> anyhow::Result<bool> {
    let mut store = load();
    let before = store.devices.len();
    store.devices.retain(|d| d.device_id != device_id);
    save(&store)?;
    Ok(store.devices.len() < before)
}

/// Best-effort wake. Without Apple credentials this only logs.
/// The payload is awareness metadata — it cannot release a pending request.
pub fn fanout_pending(digest_prefix: &str, summary: &str) {
    let store = load();
    if store.devices.is_empty() {
        return;
    }
    let have_creds = std::env::var("APNS_KEY_ID").is_ok()
        && std::env::var("APNS_TEAM_ID").is_ok()
        && std::env::var("APNS_AUTH_KEY_PATH").is_ok();
    info!(
        "apns wake digest_prefix={digest_prefix} devices={} creds={have_creds} (awareness only)",
        store.devices.len()
    );
    if !have_creds {
        return;
    }
    for rec in &store.devices {
        match decrypt_token(rec) {
            Ok(_token) => {
                // Real HTTP/2 APNs send requires provider certs; keep fail-open
                // on transport so a push outage never blocks the ceremony.
                warn!(
                    "apns send not configured beyond env presence; token hash {} for {}",
                    &rec.token_hash[..8.min(rec.token_hash.len())],
                    rec.device_id
                );
            }
            Err(e) => warn!("apns decrypt failed for {}: {e}", rec.device_id),
        }
    }
    let _ = summary;
}

#[allow(dead_code)]
pub fn store_path() -> PathBuf {
    paths::apns_devices_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_roundtrip_and_hash_not_token() {
        let dir = std::env::temp_dir().join(format!("gh-apns-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("GATEHOUSE_DATA_DIR", &dir);
        let token = "abcd1234deadbeef";
        let hash = register("phone-1", token).unwrap();
        assert_ne!(hash, token);
        assert!(!hash.contains(token));
        let store = load();
        let rec = store.devices.iter().find(|d| d.device_id == "phone-1").unwrap();
        assert_eq!(decrypt_token(rec).unwrap(), token);
        assert!(unregister("phone-1").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }
}
