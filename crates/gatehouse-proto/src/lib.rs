//! Shared types for the gatehouse approval broker: the canonical request
//! format, approval envelopes, the wire protocol, and well-known paths.
//!
//! Everything that feeds a digest lives in this crate so that the daemon,
//! the CLI, and future signers (Touch ID, WebAuthn) can never disagree about
//! what was approved.

pub mod envelope;
pub mod paths;
pub mod relay;
pub mod request;
pub mod wire;

pub use envelope::{ApprovalEnvelope, EnvelopeError, SigScheme};
pub use relay::{DaemonToRelay, RelayConfig, RelayMethod, RelayToDaemon};
pub use request::{GateRequest, Operation};
pub use wire::{
    AgentMsg, CtlMsg, CtlResp, DaemonMsg, DecisionStatus, GrantInfo, PendingEntry, Tier,
};

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("canonicalization failed: {0}")]
    Canonicalize(#[from] serde_json::Error),
}
