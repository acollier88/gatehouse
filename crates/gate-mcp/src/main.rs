//! Minimal MCP stdio server: `gated_exec` and `gated_fetch`.
//!
//! Wire any MCP-capable harness (Cursor, Claude Desktop, Codex, …) to this
//! binary. Tools submit through the gatehouse agent socket — exec is
//! broker-executed; fetch is policy-checked then performed by this process.

use anyhow::Context;
use gatehouse_proto::{paths, AgentMsg, DaemonMsg, DecisionStatus, GateRequest, Operation};
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
        if let Some(response) = dispatch(&msg).await {
            write_msg(&mut stdout, response).await?;
        }
    }
    Ok(())
}

/// Handle one decoded JSON-RPC message. `None` means send nothing: the message
/// carried no `id` (a notification) or no `method` (a response), and answering
/// either is a protocol violation.
async fn dispatch(msg: &Value) -> Option<Value> {
    let method = msg.get("method")?.as_str().unwrap_or("").to_string();
    let id = msg.get("id")?.clone();
    let params = msg.get("params").cloned().unwrap_or(json!({}));

    let result = match method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "gatehouse", "version": env!("CARGO_PKG_VERSION") }
        })),
        // Only reachable if a client wrongly gives these an id; the notification
        // form is already filtered out above.
        "notifications/initialized" | "initialized" => Ok(json!({})),
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

    Some(match result {
        Ok(r) => json!({"jsonrpc":"2.0","id":id,"result":r}),
        Err(message) => {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":message}})
        }
    })
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

/// Response bodies are truncated to this many bytes before being handed back.
const MAX_BODY_BYTES: usize = 32_000;

async fn gated_fetch(args: &Value) -> anyhow::Result<Value> {
    let url_str = args["url"].as_str().context("gated_fetch requires url")?;
    let url = Url::parse(url_str).context("bad url")?;
    // Policy speaks in host/port; anything else has no gate to pass.
    if !matches!(url.scheme(), "http" | "https") {
        return Ok(tool_error(&format!(
            "gated_fetch supports http/https only, got {}",
            url.scheme()
        )));
    }
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
                // Policy cleared this host only; following a redirect would
                // reach a host no rule ever saw.
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            let resp = client.get(url_str).send().await?;
            let status = resp.status();
            if status.is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("(no location header)");
                return Ok(tool_error(&format!(
                    "HTTP {status} redirect to {location} — not followed; \
                     call gated_fetch again with that url so policy sees the new host"
                )));
            }
            let body = resp.text().await?;
            Ok(tool_ok(&truncate_body(&format!("HTTP {status}\n{body}"))))
        }
    }
}

/// Byte-bounded truncation that never splits a UTF-8 character.
fn truncate_body(text: &str) -> String {
    if text.len() <= MAX_BODY_BYTES {
        return text.to_string();
    }
    let mut end = MAX_BODY_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…\n(truncated)", &text[..end])
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn resp(msg: Value) -> Option<Value> {
        dispatch(&msg).await
    }

    #[tokio::test]
    async fn id_zero_and_string_ids_echo_verbatim() {
        let r = resp(json!({"jsonrpc":"2.0","id":0,"method":"ping"}))
            .await
            .unwrap();
        assert_eq!(r["id"], json!(0));
        let r = resp(json!({"jsonrpc":"2.0","id":"abc","method":"ping"}))
            .await
            .unwrap();
        assert_eq!(r["id"], json!("abc"));
    }

    #[tokio::test]
    async fn notifications_get_no_response() {
        for method in [
            "notifications/initialized",
            "notifications/cancelled",
            "notifications/progress",
            "some/unknown/notification",
        ] {
            assert!(
                resp(json!({"jsonrpc":"2.0","method":method})).await.is_none(),
                "{method} must not be answered"
            );
        }
    }

    #[tokio::test]
    async fn responses_are_not_answered() {
        assert!(resp(json!({"jsonrpc":"2.0","id":1,"result":{}}))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn unknown_method_is_a_jsonrpc_error() {
        let r = resp(json!({"jsonrpc":"2.0","id":7,"method":"bogus"}))
            .await
            .unwrap();
        assert_eq!(r["id"], json!(7));
        assert_eq!(r["error"]["code"], json!(-32601));
        assert!(r.get("result").is_none());
    }

    #[tokio::test]
    async fn tools_list_advertises_both_tools() {
        let r = resp(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .await
            .unwrap();
        let names: Vec<&str> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["gated_exec", "gated_fetch"]);
    }

    #[tokio::test]
    async fn unknown_tool_is_a_tool_error_not_a_protocol_error() {
        let r = resp(json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": {"name":"nope","arguments":{}}
        }))
        .await
        .unwrap();
        assert!(r.get("error").is_none());
        assert_eq!(r["result"]["isError"], json!(true));
        assert_eq!(r["result"]["content"][0]["type"], json!("text"));
    }

    #[tokio::test]
    async fn daemon_failure_maps_to_tool_error() {
        // No daemon socket in the test env: the connect error must surface as a
        // tool error, never as a JSON-RPC error.
        std::env::set_var("GATEHOUSE_RUNTIME_DIR", "/nonexistent/gatehouse-test");
        let r = resp(json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": {"name":"gated_exec","arguments":{"argv":["ls"]}}
        }))
        .await
        .unwrap();
        assert!(r.get("error").is_none());
        assert_eq!(r["result"]["isError"], json!(true));
    }

    #[tokio::test]
    async fn non_http_scheme_is_refused_before_submitting() {
        let r = resp(json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": {"name":"gated_fetch","arguments":{"url":"file:///etc/passwd"}}
        }))
        .await
        .unwrap();
        assert_eq!(r["result"]["isError"], json!(true));
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("http/https only"), "got: {text}");
    }

    #[test]
    fn truncation_never_splits_a_utf8_character() {
        // A multi-byte char straddling the cut point must not panic or corrupt.
        let text = "é".repeat(MAX_BODY_BYTES);
        let out = truncate_body(&text);
        assert!(out.ends_with("…\n(truncated)"));
        assert!(out.len() < text.len());
    }

    #[test]
    fn short_bodies_pass_through_unchanged() {
        assert_eq!(truncate_body("hello"), "hello");
    }
}
