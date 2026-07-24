//! Daemon ↔ relay control-plane messages.
//!
//! The phone talks HTTPS to the relay; the relay forwards each API call to
//! the daemon over an mTLS WebSocket. Ceremonies and passkey verification
//! always happen on the daemon — a compromised relay cannot forge an
//! approval without a valid WebAuthn assertion.

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
    Hello { enrolled: usize },
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
}
