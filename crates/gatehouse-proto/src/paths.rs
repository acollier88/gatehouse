//! Well-known filesystem locations shared by the daemon and CLI.
//!
//! Overridable via `GATEHOUSE_RUNTIME_DIR` so tests and containerized
//! deployments can relocate the sockets.

use std::path::PathBuf;

fn runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("GATEHOUSE_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .expect("no home directory")
        .join(".gatehouse")
        .join("run")
}

/// Sandbox-facing socket: submit-only.
pub fn agent_sock() -> PathBuf {
    runtime_dir().join("agent.sock")
}

/// Operator-facing socket: approve/deny/grant/status.
pub fn ctl_sock() -> PathBuf {
    runtime_dir().join("ctl.sock")
}

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("GATEHOUSE_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .expect("no config directory")
        .join("gatehouse")
}

pub fn policy_path() -> PathBuf {
    config_dir().join("policy.toml")
}

pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("GATEHOUSE_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .expect("no data directory")
        .join("gatehouse")
}

pub fn audit_path() -> PathBuf {
    data_dir().join("audit.jsonl")
}

/// Enrolled passkeys (webauthn-rs `Passkey` list, JSON).
pub fn passkeys_path() -> PathBuf {
    data_dir().join("passkeys.json")
}

/// Where the daemon advertises its approval-page endpoint: `{port, token}`.
/// Lives in the runtime dir (0600) so only the operator's user can read it.
pub fn http_info_path() -> PathBuf {
    agent_sock().parent().unwrap().join("http.json")
}
