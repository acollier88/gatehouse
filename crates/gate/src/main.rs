mod hook;
mod ipc;

use std::io::Write as _;
use std::process::ExitCode;

use anyhow::{bail, Context};
use base64::Engine;
use clap::{Parser, Subcommand};
use gatehouse_proto::{
    paths, AgentMsg, CtlMsg, CtlResp, DaemonMsg, DecisionStatus, GateRequest, Operation,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser)]
#[command(name = "gate", about = "Gatehouse client — route agent operations through the approval broker")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Submit a command; on approval the daemon executes it and streams
    /// output back (broker-executes).
    Run {
        #[arg(long, default_value = "cli")]
        harness: String,
        /// Environment variable names to pass through to the child.
        #[arg(long = "env")]
        env: Vec<String>,
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// Submit a command for a decision only (advisory mode for harness
    /// hooks). Prints JSON; exit 0 = allowed, 2 = denied.
    Ask {
        #[arg(long, default_value = "hook")]
        harness: String,
        #[arg(long)]
        json: bool,
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// List requests waiting for approval.
    Pending,
    /// Approve a pending request by digest prefix.
    Approve { digest_prefix: String },
    /// Deny a pending request by digest prefix.
    Deny { digest_prefix: String },
    /// Auto-allow an argv glob for a while, e.g. `gate grant "npm install*" --for 1h`.
    Grant {
        argv_glob: String,
        #[arg(long = "for", default_value = "1h")]
        ttl: String,
    },
    /// Show daemon status.
    Status,
    /// Open the approval page to enroll a passkey (Touch ID on macOS).
    Enroll,
    /// Open the approval page to act on pending requests.
    Approvals,
    /// Harness hook adapters (reads hook JSON on stdin). Currently:
    /// `gate hook claude-code` for Claude Code PreToolUse.
    Hook { adapter: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { harness, env, argv } => submit(harness, env, argv, true, false).await,
        Cmd::Ask { harness, json, argv } => submit(harness, vec![], argv, false, json).await,
        Cmd::Pending => ctl(CtlMsg::Pending).await,
        Cmd::Approve { digest_prefix } => ctl(CtlMsg::Approve { digest_prefix }).await,
        Cmd::Deny { digest_prefix } => ctl(CtlMsg::Deny { digest_prefix }).await,
        Cmd::Grant { argv_glob, ttl } => {
            let ttl_secs = parse_ttl(&ttl)?;
            ctl(CtlMsg::Grant { argv_glob, ttl_secs }).await
        }
        Cmd::Status => ctl(CtlMsg::Status).await,
        Cmd::Enroll | Cmd::Approvals => open_approval_page(),
        Cmd::Hook { adapter } => match adapter.as_str() {
            "claude-code" => hook::run_claude_code().await,
            other => {
                eprintln!("unknown hook adapter: {other} (supported: claude-code)");
                Ok(ExitCode::FAILURE)
            }
        },
    }
}

/// Prefer the phone relay URL when configured; else the localhost page.
fn open_approval_page() -> anyhow::Result<ExitCode> {
    let url = if let Ok(text) = std::fs::read_to_string(paths::relay_config_path()) {
        #[derive(serde::Deserialize)]
        struct RelayCfg {
            origin: String,
            phone_token: String,
        }
        let cfg: RelayCfg = serde_json::from_str(&text)?;
        format!("{}/?t={}", cfg.origin.trim_end_matches('/'), cfg.phone_token)
    } else {
        #[derive(serde::Deserialize)]
        struct HttpInfo {
            port: u16,
            token: String,
        }
        let path = paths::http_info_path();
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "cannot read {} — is gatehoused running? (or run relay-init for phone URL)",
                path.display()
            )
        })?;
        let info: HttpInfo = serde_json::from_str(&text)?;
        format!("http://localhost:{}/?t={}", info.port, info.token)
    };
    println!("approval page: {url}");
    #[cfg(target_os = "macos")]
    let launch = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(target_os = "windows")]
    let launch = std::process::Command::new("cmd")
        .args(["/C", "start", "", &url])
        .spawn();
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let launch = std::process::Command::new("xdg-open").arg(&url).spawn();
    if let Err(e) = launch {
        eprintln!("could not launch browser ({e}); open the URL manually");
    }
    Ok(ExitCode::SUCCESS)
}

fn session_id() -> String {
    std::env::var("GATEHOUSE_SESSION").unwrap_or_else(|_| format!("cli-{}", std::process::id()))
}

async fn submit(
    harness: String,
    env_allowlist: Vec<String>,
    argv: Vec<String>,
    execute: bool,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let cwd = std::env::current_dir()?
        .to_str()
        .context("cwd is not utf-8")?
        .to_string();
    let request = GateRequest {
        harness,
        session_id: session_id(),
        env_allowlist,
        op: Operation::Exec { argv, cwd },
    };

    let (read, mut write) = ipc::connect_agent().await?;
    let mut msg = serde_json::to_string(&AgentMsg::Submit { request, execute })?;
    msg.push('\n');
    write.write_all(msg.as_bytes()).await?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut lines = BufReader::new(read).lines();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    while let Some(line) = lines.next_line().await? {
        match serde_json::from_str::<DaemonMsg>(&line)? {
            DaemonMsg::Decision { digest, tier, status, summary } => match status {
                DecisionStatus::Pending => {
                    eprintln!(
                        "gate: waiting for approval [{}] ({tier}): {summary}",
                        &digest[..8]
                    );
                }
                DecisionStatus::Denied => {
                    if json {
                        println!("{{\"decision\":\"denied\",\"digest\":\"{digest}\"}}");
                    } else {
                        eprintln!("gate: denied ({tier}): {summary}");
                    }
                    return Ok(ExitCode::from(2));
                }
                DecisionStatus::Allowed => {
                    if !execute {
                        if json {
                            println!("{{\"decision\":\"allowed\",\"digest\":\"{digest}\"}}");
                        } else {
                            eprintln!("gate: allowed: {summary}");
                        }
                        return Ok(ExitCode::SUCCESS);
                    }
                    // broker-executes: output messages follow.
                }
            },
            DaemonMsg::Stdout { b64: data } => {
                stdout.write_all(&b64.decode(data.as_bytes())?)?;
                stdout.flush()?;
            }
            DaemonMsg::Stderr { b64: data } => {
                stderr.write_all(&b64.decode(data.as_bytes())?)?;
                stderr.flush()?;
            }
            DaemonMsg::Exit { code } => {
                return Ok(ExitCode::from(code.clamp(0, 255) as u8));
            }
            DaemonMsg::Error { message } => {
                eprintln!("gate: daemon error: {message}");
                return Ok(ExitCode::from(125));
            }
        }
    }
    eprintln!("gate: daemon closed the connection unexpectedly");
    Ok(ExitCode::from(125))
}

async fn ctl(msg: CtlMsg) -> anyhow::Result<ExitCode> {
    let (read, mut write) = ipc::connect_ctl().await?;
    let mut line = serde_json::to_string(&msg)?;
    line.push('\n');
    write.write_all(line.as_bytes()).await?;

    let mut lines = BufReader::new(read).lines();
    let Some(resp) = lines.next_line().await? else {
        bail!("no response from daemon");
    };
    match serde_json::from_str::<CtlResp>(&resp)? {
        CtlResp::Ok { message } => {
            println!("{message}");
            Ok(ExitCode::SUCCESS)
        }
        CtlResp::Error { message } => {
            eprintln!("error: {message}");
            Ok(ExitCode::FAILURE)
        }
        CtlResp::Pending { entries } => {
            if entries.is_empty() {
                println!("no pending requests");
            }
            for e in entries {
                println!(
                    "[{}] {:>10} {:>4}s {} ({})",
                    &e.digest[..8],
                    e.tier.to_string(),
                    e.age_secs,
                    e.summary,
                    e.harness
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        CtlResp::Status { version, pending, grants, uptime_secs } => {
            println!("gatehoused up {uptime_secs}s (protocol v{version})");
            println!("pending approvals: {pending}");
            if grants.is_empty() {
                println!("active grants: none");
            } else {
                println!("active grants:");
                for g in grants {
                    println!("  `{}` for {}s more", g.argv_glob, g.expires_in_secs);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Parse "90", "90s", "30m", "2h", "1d" into seconds.
fn parse_ttl(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => bail!("bad duration: {s}"),
    };
    let n: u64 = num.parse().with_context(|| format!("bad duration: {s}"))?;
    Ok(n * mult)
}
