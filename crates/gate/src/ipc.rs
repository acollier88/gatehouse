//! Connect to gatehoused agent/ctl endpoints (Unix socket or loopback TCP).

use anyhow::Context;
use gatehouse_proto::ipc::{resolve_agent_endpoint, resolve_ctl_endpoint, Endpoint};
use gatehouse_proto::Transport;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

#[cfg(unix)]
use tokio::net::UnixStream;

pub async fn connect_agent() -> anyhow::Result<(
    Box<dyn AsyncRead + Unpin + Send>,
    Box<dyn AsyncWrite + Unpin + Send>,
)> {
    let ep = resolve_agent_endpoint().context("cannot resolve agent endpoint")?;
    connect(&ep)
        .await
        .with_context(|| format!("cannot reach gatehoused at {}", ep.display()))
}

pub async fn connect_ctl() -> anyhow::Result<(
    Box<dyn AsyncRead + Unpin + Send>,
    Box<dyn AsyncWrite + Unpin + Send>,
)> {
    let ep = resolve_ctl_endpoint().context("cannot resolve ctl endpoint")?;
    connect(&ep)
        .await
        .with_context(|| format!("cannot reach gatehoused ctl at {}", ep.display()))
}

async fn connect(
    ep: &Endpoint,
) -> anyhow::Result<(
    Box<dyn AsyncRead + Unpin + Send>,
    Box<dyn AsyncWrite + Unpin + Send>,
)> {
    match ep.transport {
        Transport::Tcp => {
            let host = ep.host.as_deref().unwrap_or("127.0.0.1");
            let port = ep.port.context("tcp endpoint missing port")?;
            let mut stream = TcpStream::connect((host, port)).await?;
            let token = ep.token.as_deref().unwrap_or("");
            stream
                .write_all(format!("AUTH {token}\n").as_bytes())
                .await?;
            let (r, w) = stream.into_split();
            Ok((Box::new(r), Box::new(w)))
        }
        Transport::Unix => {
            #[cfg(unix)]
            {
                let path = ep.path.as_deref().context("unix endpoint missing path")?;
                let stream = UnixStream::connect(path).await?;
                let (r, w) = stream.into_split();
                Ok((Box::new(r), Box::new(w)))
            }
            #[cfg(not(unix))]
            {
                anyhow::bail!("unix sockets not supported on this platform");
            }
        }
    }
}
