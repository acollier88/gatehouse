//! Device enrollment for token-authenticated / hosted relays.
//!
//! Each enrolled device owns two CSPRNG secrets: `token` for the broker's
//! control-plane WebSocket and `phone_token` for that device's phone. Nothing
//! is shared between devices, because in hosted mode a shared phone token is
//! a cross-tenant read/deny/enroll primitive.
//!
//! The phone token *is* the device selector: [`authorize_phone`] derives the
//! device from the presented token and only then checks that any explicit
//! `?d=` agrees. Comparisons scan every record in constant time.

use std::path::Path;

use anyhow::{bail, Context};
use gatehouse_proto::{paths, DeviceCred, DeviceRecord};
use subtle::ConstantTimeEq;
use tracing::info;

use crate::certs::RelayMaterial;

/// Device key for the legacy single-tenant mTLS dial-out. Not enrollable:
/// no `DeviceRecord` may claim it.
pub const MTLS_DEVICE: &str = "_mtls";

pub fn load_devices() -> anyhow::Result<Vec<DeviceRecord>> {
    let path = paths::devices_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let text = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn save_devices(devices: &[DeviceRecord]) -> anyhow::Result<()> {
    let path = paths::devices_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    let text = serde_json::to_string_pretty(devices)?;
    std::fs::write(&path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn enroll(label: &str) -> anyhow::Result<DeviceRecord> {
    let mut devices = load_devices()?;
    let device_id = format!("dev_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let rec = DeviceRecord {
        device_id: device_id.clone(),
        token: new_token(),
        phone_token: new_token(),
        label: label.to_string(),
        created_at: now_unix(),
    };
    devices.push(rec.clone());
    save_devices(&devices)?;
    info!("enrolled device {device_id} ({label})");
    Ok(rec)
}

pub fn list() -> anyhow::Result<()> {
    let devices = load_devices()?;
    if devices.is_empty() {
        println!("(no devices enrolled)");
        return Ok(());
    }
    for d in devices {
        println!(
            "{}  {}  created={}",
            d.device_id,
            if d.label.is_empty() { "-" } else { &d.label },
            d.created_at
        );
    }
    Ok(())
}

/// Write a daemon-side credential file the broker can load for dial-out.
pub fn write_daemon_cred(
    rec: &DeviceRecord,
    endpoint: &str,
    dest: Option<&Path>,
) -> anyhow::Result<DeviceCred> {
    let material = RelayMaterial::load()?;
    let cred = DeviceCred {
        device_id: rec.device_id.clone(),
        token: rec.token.clone(),
        endpoint: endpoint.trim_end_matches('/').to_string(),
        rp_id: material.config.rp_id.clone(),
        origin: material.config.origin.clone(),
        phone_token: Some(rec.phone_token.clone()),
    };
    let path = dest
        .map(|p| p.to_path_buf())
        .unwrap_or_else(paths::device_cred_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&cred)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("wrote daemon credential: {}", path.display());
    if let Some(url) = cred.phone_url() {
        println!("phone URL (device-scoped): {url}");
    }
    Ok(cred)
}

pub fn find(device_id: &str) -> anyhow::Result<DeviceRecord> {
    load_devices()?
        .into_iter()
        .find(|d| d.device_id == device_id)
        .with_context(|| format!("unknown device_id {device_id}"))
}

/// Constant-time select over every record: an early-exit `==` leaks how much
/// of a guessed token was right.
fn select<F>(devices: &[DeviceRecord], presented: &str, field: F) -> Option<DeviceRecord>
where
    F: Fn(&DeviceRecord) -> &str,
{
    if presented.is_empty() {
        return None;
    }
    let mut hit: Option<&DeviceRecord> = None;
    for d in devices {
        let secret = field(d);
        let same = secret.len() == presented.len()
            && bool::from(secret.as_bytes().ct_eq(presented.as_bytes()));
        if same {
            hit = Some(d);
        }
    }
    hit.cloned()
}

/// The device whose control-plane token this is (daemon WebSocket auth).
pub fn select_by_token(devices: &[DeviceRecord], token: &str) -> Option<DeviceRecord> {
    select(devices, token, |d| &d.token)
}

/// The device whose phone bearer this is.
pub fn select_by_phone_token(devices: &[DeviceRecord], token: &str) -> Option<DeviceRecord> {
    select(devices, token, |d| &d.phone_token)
}

pub fn lookup_token(token: &str) -> anyhow::Result<Option<DeviceRecord>> {
    Ok(select_by_token(&load_devices()?, token))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Authz {
    /// Token belongs to this enrolled device.
    Device(String),
    /// Token is the relay-wide phone bearer: legacy single-tenant mTLS link.
    LegacyMtls,
    /// Token matches nothing.
    Unauthenticated,
    /// Token is valid but addresses a device it does not own.
    WrongDevice,
}

/// Authorize one phone API call.
///
/// The token identifies the device; `requested` (`?d=` / `X-Gatehouse-Device`)
/// is only ever a cross-check, never the selector, so holding device A's token
/// can never address device B. The relay-wide `phone_token` from relay config
/// authorizes the legacy single-tenant mTLS link and nothing else.
pub fn authorize_phone(
    devices: &[DeviceRecord],
    relay_phone_token: &str,
    presented: &str,
    requested: Option<&str>,
) -> Authz {
    let requested = requested.filter(|s| !s.is_empty());
    if let Some(rec) = select_by_phone_token(devices, presented) {
        return match requested {
            Some(d) if d != rec.device_id => Authz::WrongDevice,
            _ => Authz::Device(rec.device_id),
        };
    }
    let legacy_ok = !relay_phone_token.is_empty()
        && presented.len() == relay_phone_token.len()
        && bool::from(presented.as_bytes().ct_eq(relay_phone_token.as_bytes()));
    if legacy_ok {
        return match requested {
            Some(d) if d != MTLS_DEVICE => Authz::WrongDevice,
            _ => Authz::LegacyMtls,
        };
    }
    Authz::Unauthenticated
}

pub fn print_pair_instructions(rec: &DeviceRecord, endpoint: &str) {
    let material = RelayMaterial::load().ok();
    println!();
    println!("Device enrolled: {} ({})", rec.device_id, rec.label);
    println!("On the machine running gatehoused:");
    println!(
        "  gatehoused device-cred --device-id {} --endpoint {} --write",
        rec.device_id, endpoint
    );
    println!("  # copies device.json, then: gatehoused --no-open");
    println!("Or without a file:");
    println!(
        "  gatehoused --relay-url {endpoint} --relay-token {} --no-open",
        rec.token
    );
    if let Some(m) = material {
        println!();
        // Device-scoped: this token authorizes this device_id and no other.
        println!(
            "Phone URL (bind to this device): {}/?t={}&d={}",
            m.config.origin, rec.phone_token, rec.device_id
        );
        println!(
            "rp_id={} — enroll passkeys against that host on the phone.",
            m.config.rp_id
        );
    }
}

pub fn require_relay_config() -> anyhow::Result<gatehouse_proto::RelayConfig> {
    let path = paths::relay_config_path();
    if !path.exists() {
        bail!("no relay config; run gatehoused relay-init first");
    }
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn new_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY_TOKEN: &str = "relay-wide-phone-token";

    fn devices() -> Vec<DeviceRecord> {
        vec![
            DeviceRecord {
                device_id: "dev_aaa".into(),
                token: "ws-token-a".into(),
                phone_token: "phone-token-a".into(),
                label: "a".into(),
                created_at: 0,
            },
            DeviceRecord {
                device_id: "dev_bbb".into(),
                token: "ws-token-b".into(),
                phone_token: "phone-token-b".into(),
                label: "b".into(),
                created_at: 0,
            },
        ]
    }

    #[test]
    fn enrollment_mints_distinct_secrets() {
        // Not a store test: the two secrets must never be the same value, or
        // a phone bearer would also authenticate a control-plane socket.
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn right_token_right_device_passes() {
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, "phone-token-a", Some("dev_aaa")),
            Authz::Device("dev_aaa".into())
        );
        // `?d=` is optional; the token alone names the device.
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, "phone-token-b", None),
            Authz::Device("dev_bbb".into())
        );
    }

    /// The cross-tenant case: device A's phone must not address device B.
    #[test]
    fn right_token_wrong_device_fails() {
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, "phone-token-a", Some("dev_bbb")),
            Authz::WrongDevice
        );
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, "phone-token-b", Some("dev_aaa")),
            Authz::WrongDevice
        );
    }

    #[test]
    fn unknown_or_empty_token_is_unauthenticated() {
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, "phone-token-c", Some("dev_aaa")),
            Authz::Unauthenticated
        );
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, "", None),
            Authz::Unauthenticated
        );
        assert_eq!(
            authorize_phone(&devices(), "", "", None),
            Authz::Unauthenticated
        );
    }

    /// The relay-wide token is the legacy single-tenant identity only: it must
    /// not reach an enrolled device.
    #[test]
    fn relay_token_reaches_only_the_mtls_link() {
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, RELAY_TOKEN, None),
            Authz::LegacyMtls
        );
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, RELAY_TOKEN, Some(MTLS_DEVICE)),
            Authz::LegacyMtls
        );
        assert_eq!(
            authorize_phone(&devices(), RELAY_TOKEN, RELAY_TOKEN, Some("dev_aaa")),
            Authz::WrongDevice
        );
    }

    #[test]
    fn lookup_selects_by_secret_and_rejects_unknown() {
        let d = devices();
        assert_eq!(
            select_by_token(&d, "ws-token-b").unwrap().device_id,
            "dev_bbb"
        );
        assert!(select_by_token(&d, "ws-token-c").is_none());
        assert!(select_by_token(&d, "").is_none());
        assert!(select_by_token(&[], "ws-token-a").is_none());
        // Token spaces do not cross: a phone bearer is not a WS credential.
        assert!(select_by_token(&d, "phone-token-a").is_none());
        assert!(select_by_phone_token(&d, "ws-token-a").is_none());
        // A prefix of a real token must not select it.
        assert!(select_by_phone_token(&d, "phone-token-").is_none());
    }
}
