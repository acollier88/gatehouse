//! Daemon ↔ relay control-plane messages.
//!
//! The phone talks HTTPS to the relay; the relay forwards each API call to
//! the daemon over an mTLS WebSocket. Ceremonies and passkey verification
//! always happen on the daemon — a compromised relay cannot forge an approval
//! without a valid WebAuthn assertion, and cannot redirect one onto another
//! request because the challenge is derived from the request digest. It does
//! still serve the page; see docs/threat-model.md.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One RPC from relay → daemon.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayToDaemon {
    Rpc {
        id: String,
        method: RelayMethod,
        #[serde(default)]
        body: Value,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayMethod {
    Pending,
    RegisterStart,
    RegisterFinish,
    ApproveStart,
    ApproveFinish,
    Deny,
}

/// Replies and events from daemon → relay.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonToRelay {
    Hello {
        enrolled: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    RpcOk { id: String, body: Value },
    RpcErr { id: String, message: String },
}

/// Persisted relay bootstrap (certs live beside this file).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelayConfig {
    pub rp_id: String,
    pub origin: String,
    /// Bearer token phones present as `X-Gatehouse-Token` / `?t=`.
    pub phone_token: String,
    /// Default phone listen address written at init time (informational).
    pub listen: String,
    /// Default daemon mTLS listen address (informational).
    pub daemon_listen: String,
    /// How phones reach this relay: `tailscale`, `custom`, `localhost`, `hosted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Daemon control-plane auth: `mtls` (default), `token`, or `both`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_auth: Option<String>,
}

/// One enrolled broker device allowed to dial the hosted/self-hosted relay.
///
/// Two independent secrets, both CSPRNG and both scoped to this device alone:
/// `token` authenticates the broker's control-plane WebSocket, `phone_token`
/// authenticates that device's phone. Neither is shared between tenants — a
/// shared phone token would let any tenant address any other tenant's broker.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceRecord {
    pub device_id: String,
    pub token: String,
    /// Phone bearer for this device. Deliberately not `#[serde(default)]`:
    /// a devices.json written before per-device tokens must fail loudly
    /// rather than load with an empty (unauthenticatable) secret.
    pub phone_token: String,
    #[serde(default)]
    pub label: String,
    pub created_at: i64,
}

/// Credentials the daemon stores to dial a token-auth relay.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceCred {
    pub device_id: String,
    pub token: String,
    /// wss/https base for the daemon control plane (host:port, no /ws).
    pub endpoint: String,
    pub rp_id: String,
    pub origin: String,
    /// This device's own phone bearer, so the daemon can surface
    /// `origin/?t=…&d=…`. Never the relay-wide phone token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_token: Option<String>,
}

impl DeviceCred {
    pub fn phone_url(&self) -> Option<String> {
        let t = self.phone_token.as_ref()?;
        Some(format!(
            "{}/?t={}&d={}",
            self.origin.trim_end_matches('/'),
            t,
            self.device_id
        ))
    }

    pub fn as_relay_config(&self) -> RelayConfig {
        RelayConfig {
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            phone_token: self.phone_token.clone().unwrap_or_default(),
            listen: String::new(),
            daemon_listen: String::new(),
            transport: Some("hosted".into()),
            daemon_auth: Some("token".into()),
        }
    }
}

/// Optional daemon-side pointer (`~/.config/gatehouse/relay.toml`).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RelayToml {
    pub endpoint: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}
