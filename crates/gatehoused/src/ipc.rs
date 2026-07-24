//! Bind local agent/ctl listeners (Unix socket or loopback TCP).

use std::path::Path;

use gatehouse_proto::ipc::{
    self, agent_endpoint_path, ctl_endpoint_path, prefer_tcp, write_endpoint, Endpoint,
};
use gatehouse_proto::paths;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::info;

#[cfg(unix)]
use tokio::net::UnixListener;

pub enum LocalListener {
    #[cfg(unix)]
    Unix(UnixListener),
    Tcp {
        listener: TcpListener,
        token: String,
    },
}

pub async fn bind_agent() -> anyhow::Result<(LocalListener, Endpoint)> {
    bind_named("agent", &paths::agent_sock(), &agent_endpoint_path()).await
}

pub async fn bind_ctl() -> anyhow::Result<(LocalListener, Endpoint)> {
    bind_named("ctl", &paths::ctl_sock(), &ctl_endpoint_path()).await
}

async fn bind_named(
    label: &str,
    unix_path: &Path,
    endpoint_path: &Path,
) -> anyhow::Result<(LocalListener, Endpoint)> {
    if prefer_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let token = ipc::new_token();
        let ep = Endpoint::tcp("127.0.0.1", port, &token);
        write_endpoint(endpoint_path, &ep)?;
        info!("{label} ipc: {}", ep.display());
        return Ok((LocalListener::Tcp { listener, token }, ep));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if unix_path.exists() {
            std::fs::remove_file(unix_path)?;
        }
        if let Some(parent) = unix_path.parent() {
            std::fs::create_dir_all(parent)?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        let listener = UnixListener::bind(unix_path)?;
        std::fs::set_permissions(unix_path, std::fs::Permissions::from_mode(0o600))?;
        let ep = Endpoint::unix(unix_path.to_string_lossy());
        write_endpoint(endpoint_path, &ep)?;
        info!("{label} ipc: {}", ep.display());
        return Ok((LocalListener::Unix(listener), ep));
    }

    #[cfg(not(unix))]
    {
        let _ = (label, unix_path, endpoint_path);
        anyhow::bail!("unix sockets unavailable; set GATEHOUSE_IPC=tcp");
    }
}

pub async fn accept(
    listener: &LocalListener,
) -> anyhow::Result<(
    Box<dyn AsyncRead + Unpin + Send>,
    Box<dyn AsyncWrite + Unpin + Send>,
)> {
    match listener {
        #[cfg(unix)]
        LocalListener::Unix(l) => {
            let (stream, _) = l.accept().await?;
            let (r, w) = stream.into_split();
            Ok((Box::new(r), Box::new(w)))
        }
        LocalListener::Tcp { listener, token } => {
            let (stream, _) = listener.accept().await?;
            let (r, mut w) = stream.into_split();
            let mut r = BufReader::new(r);
            let mut auth_line = String::new();
            r.read_line(&mut auth_line).await?;
            let auth = auth_line.trim_end_matches(['\r', '\n']);
            let expected = format!("AUTH {token}");
            if auth != expected {
                let _ = w
                    .write_all(b"{\"type\":\"error\",\"message\":\"unauthorized\"}\n")
                    .await;
                anyhow::bail!("tcp AUTH failed");
            }
            Ok((Box::new(r), Box::new(w)))
        }
    }
}

pub fn cleanup(agent: &Endpoint, ctl: &Endpoint) {
    let _ = std::fs::remove_file(agent_endpoint_path());
    let _ = std::fs::remove_file(ctl_endpoint_path());
    if let Some(p) = &agent.path {
        let _ = std::fs::remove_file(p);
    }
    if let Some(p) = &ctl.path {
        let _ = std::fs::remove_file(p);
    }
}
