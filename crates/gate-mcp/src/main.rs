//! Minimal MCP stdio server: `gated_exec` and `gated_fetch`.
//!
//! Wire any MCP-capable harness (Cursor, Claude Desktop, Codex, …) to this
//! binary. Tools submit through the gatehouse agent socket — exec is
//! broker-executed; fetch is policy-checked then performed by this process.

use anyhow::Context;
use gatehouse_proto::{
    paths, AgentMsg, DaemonMsg, DecisionStatus, GateRequest, Operation,
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                write_msg(
                    &mut stdout,
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":e.to_string()}}),
                )
                .await?;
                continue;
            }
        };
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg["method"].as_str().unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(json!({}));

        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "gatehouse", "version": env!("CARGO_PKG_VERSION") }
            })),
            "notifications/initialized" | "initialized" => {
                // notification — no response
                continue;
            }
            "tools/list" => Ok(json!({
                "tools": [
                    {
                        "name": "gated_exec",
                        "description": "Run a command through the gatehouse broker (broker-executes on allow).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": { "type": "string", "description": "Shell command string" },
                                "argv": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Preferred: explicit argv (no shell)"
                                }
                            }
                        }
                    },
                    {
                        "name": "gated_fetch",
                        "description": "HTTP GET after gatehouse policy allows connecting to the host.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["url"],
                            "properties": {
                                "url": { "type": "string" }
                            }
                        }
                    }
                ]
            })),
            "tools/call" => match handle_tool_call(&params).await {
                Ok(v) => Ok(v),
                Err(e) => Ok(tool_error(&e.to_string())),
            },
            "ping" => Ok(json!({})),
            _ => Err(format!("method not found: {method}")),
        };

        match result {
            Ok(r) => {
                write_msg(&mut stdout, json!({"jsonrpc":"2.0","id":id,"result":r})).await?;
            }
            Err(message) => {
                write_msg(
                    &mut stdout,
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":message}}),
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn write_msg(out: &mut tokio::io::Stdout, v: Value) -> anyhow::Result<()> {
    let mut line = serde_json::to_string(&v)?;
    line.push('\n');
    out.write_all(line.as_bytes()).await?;
    out.flush().await?;
    Ok(())
}

fn tool_error(msg: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": msg }],
        "isError": true
    })
}

fn tool_ok(msg: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": msg }],
        "isError": false
    })
}

async fn handle_tool_call(params: &Value) -> anyhow::Result<Value> {
    let name = params["name"].as_str().unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    match name {
        "gated_exec" => gated_exec(&args).await,
        "gated_fetch" => gated_fetch(&args).await,
        other => Ok(tool_error(&format!("unknown tool: {other}"))),
    }
}

async fn gated_exec(args: &Value) -> anyhow::Result<Value> {
    let cwd = std::env::current_dir()?
        .to_str()
        .context("cwd")?
        .to_string();
    let argv = if let Some(arr) = args["argv"].as_array() {
        arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>()
    } else if let Some(cmd) = args["command"].as_str() {
        vec!["sh".into(), "-c".into(), cmd.to_string()]
    } else {
        return Ok(tool_error("gated_exec requires argv or command"));
    };
    if argv.is_empty() {
        return Ok(tool_error("empty argv"));
    }

    let request = GateRequest {
        harness: "mcp".into(),
        session_id: format!("mcp-{}", std::process::id()),
        env_allowlist: vec![],
        op: Operation::Exec { argv, cwd },
    };
    match submit(request, true).await? {
        SubmitResult::Denied { summary } => Ok(tool_error(&format!("denied: {summary}"))),
        SubmitResult::Output { stdout, stderr, code } => {
            let mut text = String::new();
            if !stdout.is_empty() {
                text.push_str(&stdout);
            }
            if !stderr.is_empty() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&stderr);
            }
            if text.is_empty() {
                text = format!("(exit {code})");
            }
            let mut v = tool_ok(&text);
            if code != 0 {
                v["isError"] = json!(true);
            }
            Ok(v)
        }
    }
}

async fn gated_fetch(args: &Value) -> anyhow::Result<Value> {
    let url_str = args["url"]
        .as_str()
        .context("gated_fetch requires url")?;
    let url = Url::parse(url_str).context("bad url")?;
    let host = url.host_str().context("url missing host")?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    let request = GateRequest {
        harness: "mcp".into(),
        session_id: format!("mcp-{}", std::process::id()),
        env_allowlist: vec![],
        op: Operation::Net { host, port },
    };
    match submit(request, false).await? {
        SubmitResult::Denied { summary } => Ok(tool_error(&format!("denied: {summary}"))),
        SubmitResult::Output { .. } => {
            // Allowed — perform the GET in this process (broker does not fetch).
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?;
            let resp = client.get(url_str).send().await?;
            let status = resp.status();
            let body = resp.text().await?;
            let text = format!("HTTP {status}\n{body}");
            let truncated = if text.len() > 32_000 {
                format!("{}…\n(truncated)", &text[..32_000])
            } else {
                text
            };
            Ok(tool_ok(&truncated))
        }
    }
}

enum SubmitResult {
    Denied { summary: String },
    Output {
        stdout: String,
        stderr: String,
        code: i32,
    },
}

async fn submit(request: GateRequest, execute: bool) -> anyhow::Result<SubmitResult> {
    let sock = paths::agent_sock();
    let stream = UnixStream::connect(&sock)
        .await
        .with_context(|| format!("connect {}: is gatehoused running?", sock.display()))?;
    let (read, mut write) = stream.into_split();
    let mut msg = serde_json::to_string(&AgentMsg::Submit { request, execute })?;
    msg.push('\n');
    write.write_all(msg.as_bytes()).await?;

    let mut lines = BufReader::new(read).lines();
    let mut stdout = String::new();
    let mut stderr = String::new();
    let b64 = base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    while let Some(line) = lines.next_line().await? {
        match serde_json::from_str::<DaemonMsg>(&line)? {
            DaemonMsg::Decision {
                status: DecisionStatus::Denied,
                summary,
                ..
            } => return Ok(SubmitResult::Denied { summary }),
            DaemonMsg::Decision {
                status: DecisionStatus::Allowed,
                ..
            } if !execute => {
                return Ok(SubmitResult::Output {
                    stdout: String::new(),
                    stderr: String::new(),
                    code: 0,
                });
            }
            DaemonMsg::Decision {
                status: DecisionStatus::Pending,
                summary,
                digest,
                ..
            } => {
                eprintln!(
                    "gate-mcp: waiting for approval [{}] {summary}",
                    &digest[..8.min(digest.len())]
                );
            }
            DaemonMsg::Decision { .. } => {}
            DaemonMsg::Stdout { b64: data } => {
                stdout.push_str(&String::from_utf8_lossy(&b64.decode(data.as_bytes())?));
            }
            DaemonMsg::Stderr { b64: data } => {
                stderr.push_str(&String::from_utf8_lossy(&b64.decode(data.as_bytes())?));
            }
            DaemonMsg::Exit { code } => {
                return Ok(SubmitResult::Output {
                    stdout,
                    stderr,
                    code,
                });
            }
            DaemonMsg::Error { message } => anyhow::bail!("daemon error: {message}"),
        }
    }
    anyhow::bail!("daemon closed connection")
}
