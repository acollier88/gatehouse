//! Newline-delimited JSON messages over two Unix sockets.
//!
//! The *agent* socket accepts only [`AgentMsg::Submit`] — it is the surface
//! mounted into a sandbox, and nothing on it can approve anything. The *ctl*
//! socket is the operator side: listing, approving, denying, granting. The
//! split is the trust boundary: a containerized agent gets the agent socket
//! mounted and never sees ctl.

use serde::{Deserialize, Serialize};

use crate::request::GateRequest;

pub const PROTOCOL_VERSION: u32 = 1;

/// Policy tier a request resolves to.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Allow,
    Ask,
    AskStrong,
    Deny,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Tier::Allow => "allow",
            Tier::Ask => "ask",
            Tier::AskStrong => "ask-strong",
            Tier::Deny => "deny",
        };
        f.write_str(s)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    Allowed,
    Denied,
    Pending,
}

/// Messages an agent (or harness adapter) may send on the agent socket.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMsg {
    Submit {
        request: GateRequest,
        /// When true and the request is an `exec` op, the daemon runs the
        /// command itself on approval and streams output back
        /// (broker-executes). When false the daemon only decides
        /// (advisory mode for harness hooks).
        execute: bool,
    },
}

/// Messages the daemon sends back on the agent socket.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMsg {
    Decision {
        digest: String,
        tier: Tier,
        status: DecisionStatus,
        summary: String,
    },
    /// Base64 chunk of child stdout (broker-executes mode only).
    Stdout { b64: String },
    /// Base64 chunk of child stderr (broker-executes mode only).
    Stderr { b64: String },
    Exit { code: i32 },
    Error { message: String },
}

/// Operator commands on the ctl socket.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CtlMsg {
    Pending,
    /// Approve a pending request by unique digest prefix.
    Approve { digest_prefix: String },
    Deny { digest_prefix: String },
    /// Session grant: argv glob auto-allowed until the TTL lapses.
    Grant { argv_glob: String, ttl_secs: u64 },
    Status,
    /// Mint a one-time code that authorises one passkey enrollment.
    EnrollCode,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingEntry {
    pub digest: String,
    pub summary: String,
    pub tier: Tier,
    pub harness: String,
    pub age_secs: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GrantInfo {
    pub argv_glob: String,
    pub expires_in_secs: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CtlResp {
    Ok { message: String },
    Pending { entries: Vec<PendingEntry> },
    /// A one-time enrollment code and how long it stays valid.
    EnrollCode { code: String, ttl_secs: u64 },
    Status {
        version: u32,
        pending: usize,
        grants: Vec<GrantInfo>,
        uptime_secs: u64,
    },
    Error { message: String },
}
