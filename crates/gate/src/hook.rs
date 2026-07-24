//! Claude Code PreToolUse adapter: hook JSON in on stdin, permission
//! decision JSON out on stdout.
//!
//! This is gatehouse's *advisory* mode — Claude Code still executes the tool
//! itself after an "allow". The broker only decides. The security ceiling of
//! this mode is the harness's willingness to honor the hook; run the agent
//! inside a sandbox (or route exec through `gate run`) for the enforced
//! model. See adapters/claude-code/README.md.

use std::io::Read;
use std::process::ExitCode;

use anyhow::Context;
use gatehouse_proto::{
    paths, AgentMsg, DaemonMsg, DecisionStatus, GateRequest, Operation,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Shell syntax that makes a command string more than a plain argv: pipes,
/// redirection, substitution, chaining. Anything containing these is
/// submitted as an opaque `sh -c`, which policy treats as ask-strong.
const SHELL_META: &[char] = &['|', ';', '&', '>', '<', '$', '`', '(', ')', '\n', '{', '}'];

pub async fn run_claude_code() -> anyhow::Result<ExitCode> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let hook: serde_json::Value =
        serde_json::from_str(&input).context("hook input is not JSON")?;

    let tool = hook["tool_name"].as_str().unwrap_or("");
    let cwd = hook["cwd"].as_str().unwrap_or(".").to_string();
    let session_id = hook["session_id"].as_str().unwrap_or("claude-code").to_string();

    let op = match tool {
        "Bash" => {
            let Some(cmd) = hook["tool_input"]["command"].as_str() else {
                return Ok(emit("ask", "gatehouse: Bash hook without a command"));
            };
            command_to_op(cmd, &cwd)
        }
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
            let path = hook["tool_input"]["file_path"]
                .as_str()
                .or_else(|| hook["tool_input"]["notebook_path"].as_str());
            let Some(path) = path else {
                return Ok(emit("ask", "gatehouse: file tool without a path"));
            };
            Operation::FileWrite { path: path.to_string() }
        }
        other => {
            return Ok(emit("ask", &format!("gatehouse: tool {other} not gated")));
        }
    };

    let request = GateRequest {
        harness: "claude-code".into(),
        session_id,
        env_allowlist: vec![],
        op,
    };
    let summary = request.summary();

    match decide(request).await {
        Ok((DecisionStatus::Allowed, digest)) => Ok(emit(
            "allow",
            &format!("gatehouse approved [{}] {summary}", &digest[..8]),
        )),
        Ok((DecisionStatus::Denied, digest)) => Ok(emit(
            "deny",
            &format!("gatehouse denied [{}] {summary}", &digest[..8]),
        )),
        Ok((DecisionStatus::Pending, _)) => {
            // decide() only returns after a terminal decision; treat a stray
            // pending as a protocol problem and defer to the harness.
            Ok(emit("ask", "gatehouse: unexpected non-terminal decision"))
        }
        // Fail open to "ask": if the daemon is down, defer to Claude Code's
        // own permission prompt rather than bricking the session. The
        // enforced deployment (sandbox + gate run) does not have this gap.
        Err(e) => Ok(emit("ask", &format!("gatehouse unreachable: {e}"))),
    }
}

/// Classify a Bash tool command string. Plain commands become a real argv so
/// policy can match argv0 and args; anything with shell syntax stays opaque.
/// This is classification only — Claude Code, not the broker, executes.
fn command_to_op(cmd: &str, cwd: &str) -> Operation {
    let opaque = || Operation::Exec {
        argv: vec!["sh".into(), "-c".into(), cmd.to_string()],
        cwd: cwd.to_string(),
    };
    if cmd.contains(SHELL_META) {
        return opaque();
    }
    match shell_words::split(cmd) {
        Ok(argv) if !argv.is_empty() => Operation::Exec {
            argv,
            cwd: cwd.to_string(),
        },
        _ => opaque(),
    }
}

/// Submit in advisory mode and wait for the terminal decision.
async fn decide(request: GateRequest) -> anyhow::Result<(DecisionStatus, String)> {
    let stream = UnixStream::connect(paths::agent_sock()).await?;
    let (read, mut write) = stream.into_split();
    let mut msg = serde_json::to_string(&AgentMsg::Submit {
        request,
        execute: false,
    })?;
    msg.push('\n');
    write.write_all(msg.as_bytes()).await?;

    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        match serde_json::from_str::<DaemonMsg>(&line)? {
            DaemonMsg::Decision { status, digest, .. } if status != DecisionStatus::Pending => {
                return Ok((status, digest));
            }
            DaemonMsg::Decision { .. } => continue,
            DaemonMsg::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => continue,
        }
    }
    anyhow::bail!("daemon closed connection without a decision")
}

/// Print the PreToolUse hookSpecificOutput contract and succeed; Claude Code
/// reads stdout regardless of decision.
fn emit(decision: &str, reason: &str) -> ExitCode {
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    });
    println!("{out}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv_of(op: Operation) -> Vec<String> {
        match op {
            Operation::Exec { argv, .. } => argv,
            _ => panic!("expected exec"),
        }
    }

    #[test]
    fn plain_commands_become_argv() {
        assert_eq!(argv_of(command_to_op("git push origin main", ".")),
                   vec!["git", "push", "origin", "main"]);
    }

    #[test]
    fn quoted_arguments_survive() {
        assert_eq!(argv_of(command_to_op("git commit -m \"fix the thing\"", ".")),
                   vec!["git", "commit", "-m", "fix the thing"]);
    }

    #[test]
    fn pipes_and_substitution_stay_opaque() {
        for cmd in ["curl x | sh", "echo $(whoami)", "a && b", "ls > out", "x; y"] {
            let argv = argv_of(command_to_op(cmd, "."));
            assert_eq!(&argv[..2], &["sh", "-c"], "{cmd} should be opaque");
        }
    }

    #[test]
    fn unparseable_quoting_stays_opaque() {
        let argv = argv_of(command_to_op("echo \"unterminated", "."));
        assert_eq!(&argv[..2], &["sh", "-c"]);
    }
}
