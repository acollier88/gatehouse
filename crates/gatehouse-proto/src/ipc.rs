//! Local IPC endpoints for agent/ctl channels.
//!
//! - **Unix (default):** Unix domain sockets (`agent.sock` / `ctl.sock`).
//! - **Windows (default):** loopback TCP + bearer token advertised in
//!   `agent.endpoint.json` / `ctl.endpoint.json`.
//! - **Override:** `GATEHOUSE_IPC=tcp` forces TCP on any OS (handy for CI).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Unix,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub transport: Transport,
    /// Absolute path for Unix sockets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Required for TCP. Clients send `AUTH <token>` as the first line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl Endpoint {
    pub fn unix(path: impl Into<String>) -> Self {
        Self {
            transport: Transport::Unix,
            path: Some(path.into()),
            host: None,
            port: None,
            token: None,
        }
    }

    pub fn tcp(host: impl Into<String>, port: u16, token: impl Into<String>) -> Self {
        Self {
            transport: Transport::Tcp,
            path: None,
            host: Some(host.into()),
            port: Some(port),
            token: Some(token.into()),
        }
    }

    pub fn display(&self) -> String {
        match self.transport {
            Transport::Unix => self.path.clone().unwrap_or_else(|| "unix:?".into()),
            Transport::Tcp => format!(
                "tcp://{}:{}/****",
                self.host.as_deref().unwrap_or("127.0.0.1"),
                self.port.unwrap_or(0)
            ),
        }
    }
}

pub fn agent_endpoint_path() -> PathBuf {
    paths::runtime_dir().join("agent.endpoint.json")
}

pub fn ctl_endpoint_path() -> PathBuf {
    paths::runtime_dir().join("ctl.endpoint.json")
}

/// Prefer TCP when on Windows or when `GATEHOUSE_IPC=tcp`.
pub fn prefer_tcp() -> bool {
    if std::env::var("GATEHOUSE_IPC")
        .map(|v| v.eq_ignore_ascii_case("tcp"))
        .unwrap_or(false)
    {
        return true;
    }
    cfg!(windows)
}

pub fn write_endpoint(path: &std::path::Path, ep: &Endpoint) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(ep).expect("endpoint json"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn read_endpoint(path: &std::path::Path) -> std::io::Result<Endpoint> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Resolve the agent endpoint: endpoint JSON if present, else legacy Unix sock.
pub fn resolve_agent_endpoint() -> std::io::Result<Endpoint> {
    let json = agent_endpoint_path();
    if json.exists() {
        return read_endpoint(&json);
    }
    #[cfg(unix)]
    {
        let sock = paths::agent_sock();
        if sock.exists() {
            return Ok(Endpoint::unix(sock.to_string_lossy()));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "no agent endpoint at {} (is gatehoused running?)",
            json.display()
        ),
    ))
}

pub fn resolve_ctl_endpoint() -> std::io::Result<Endpoint> {
    let json = ctl_endpoint_path();
    if json.exists() {
        return read_endpoint(&json);
    }
    #[cfg(unix)]
    {
        let sock = paths::ctl_sock();
        if sock.exists() {
            return Ok(Endpoint::unix(sock.to_string_lossy()));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "no ctl endpoint at {} (is gatehoused running?)",
            json.display()
        ),
    ))
}

pub fn new_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Not a CSPRNG; sufficient for loopback pairing with 0600 endpoint file.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("gh{:x}{:x}", nanos, std::process::id())
}
