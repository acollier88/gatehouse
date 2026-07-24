//! Device enrollment for token-authenticated / hosted relays.

use std::path::Path;

use anyhow::{bail, Context};
use gatehouse_proto::{paths, DeviceCred, DeviceRecord};
use tracing::info;

use crate::certs::RelayMaterial;

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
    let token = new_token();
    let rec = DeviceRecord {
        device_id: device_id.clone(),
        token: token.clone(),
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
        phone_token: Some(material.config.phone_token.clone()),
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

pub fn lookup_token(token: &str) -> anyhow::Result<Option<DeviceRecord>> {
    Ok(load_devices()?.into_iter().find(|d| d.token == token))
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
        println!(
            "Phone URL (bind to this device): {}/?t={}&d={}",
            m.config.origin, m.config.phone_token, rec.device_id
        );
        println!("rp_id={} — enroll passkeys against that host on the phone.", m.config.rp_id);
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
