//! Harness PreToolUse adapters: hook JSON in on stdin, decision out on stdout.
//!
//! This is gatehouse's *advisory* mode — the harness still executes the tool
//! after an "allow". The broker only decides. The security ceiling is the
//! harness's willingness to honor the hook; run the agent inside a sandbox
//! (or route exec through `gate run`) for the enforced model.
//!
//! Supported adapters:
//! - `claude-code` — Claude Code `hookSpecificOutput` JSON
//! - `codex` — Codex CLI lifecycle hooks (Claude-shaped stdin; exit 2 = deny)
//! - `generic` — normalized `{harness,tool,command|path,cwd,session_id}` JSON

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

#[derive(Clone, Copy)]
enum OutFormat {
    /// Claude Code PreToolUse `hookSpecificOutput` contract.
    ClaudeCode,
    /// Codex: print a short reason; exit 2 denies, 0 allows/asks.
    Codex,
    /// Simple JSON for plugins / OpenCode / custom wrappers.
    Generic,
}

pub async fn run_adapter(name: &str) -> anyhow::Result<ExitCode> {
    let (harness, format) = match name {
        "claude-code" => ("claude-code", OutFormat::ClaudeCode),
        "codex" => ("codex", OutFormat::Codex),
        "generic" => ("generic", OutFormat::Generic),
        other => {
            eprintln!(
                "unknown hook adapter: {other} (supported: claude-code, codex, generic)"
            );
            return Ok(ExitCode::FAILURE);
        }
    };

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let hook: serde_json::Value =
        serde_json::from_str(&input).context("hook input is not JSON")?;

    let parsed = parse_hook(&hook, harness);
    let (decision, reason) = match parsed {
        Parsed::Defer { reason } => ("ask", reason),
        Parsed::Request(request) => {
            let summary = request.summary();
            match decide(request).await {
                Ok((DecisionStatus::Allowed, digest)) => (
                    "allow",
                    format!("gatehouse approved [{}] {summary}", &digest[..8]),
                ),
                Ok((DecisionStatus::Denied, digest)) => (
                    "deny",
                    format!("gatehouse denied [{}] {summary}", &digest[..8]),
                ),
                Ok((DecisionStatus::Pending, _)) => (
                    "ask",
                    "gatehouse: unexpected non-terminal decision".into(),
                ),
                Err(e) => ("ask", format!("gatehouse unreachable: {e}")),
            }
        }
    };

    Ok(emit(format, decision, &reason))
}

enum Parsed {
    Request(GateRequest),
    Defer { reason: String },
}

fn parse_hook(hook: &serde_json::Value, default_harness: &str) -> Parsed {
    // Prefer explicit generic fields, then Claude/Codex-shaped ones.
    let harness = hook["harness"]
        .as_str()
        .unwrap_or(default_harness)
        .to_string();
    let cwd = first_str(hook, &["cwd", "working_directory", "workdir"])
        .unwrap_or_else(|| ".".into());
    let session_id = first_str(hook, &["session_id", "sessionId", "conversation_id"])
        .unwrap_or_else(|| harness.clone());

    let tool = first_str(hook, &["tool_name", "toolName", "tool"])
        .unwrap_or_default();
    let tool_input = hook
        .get("tool_input")
        .or_else(|| hook.get("toolInput"))
        .or_else(|| hook.get("input"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let op = match normalize_tool(&tool) {
        ToolKind::Bash => {
            let Some(cmd) = first_str(&tool_input, &["command", "cmd", "script"])
                .or_else(|| hook["command"].as_str().map(|s| s.to_string()))
            else {
                return Parsed::Defer {
                    reason: "gatehouse: bash/shell hook without a command".into(),
                };
            };
            command_to_op(&cmd, &cwd)
        }
        ToolKind::FileWrite => {
            let Some(path) = first_str(
                &tool_input,
                &["file_path", "filePath", "path", "notebook_path", "notebookPath"],
            )
            .or_else(|| first_str(hook, &["path", "file_path"]))
            else {
                return Parsed::Defer {
                    reason: "gatehouse: file tool without a path".into(),
                };
            };
            Operation::FileWrite { path }
        }
        ToolKind::Unknown => {
            // Generic adapter may pass op directly.
            if let Some(cmd) = hook["command"].as_str() {
                command_to_op(cmd, &cwd)
            } else if let Some(path) = hook["path"].as_str() {
                Operation::FileWrite {
                    path: path.to_string(),
                }
            } else {
                return Parsed::Defer {
                    reason: format!("gatehouse: tool {tool:?} not gated"),
                };
            }
        }
    };

    Parsed::Request(GateRequest {
        harness,
        session_id,
        env_allowlist: vec![],
        op,
    })
}

enum ToolKind {
    Bash,
    FileWrite,
    Unknown,
}

fn normalize_tool(tool: &str) -> ToolKind {
    match tool {
        "Bash" | "bash" | "Shell" | "shell" | "execute" | "run_terminal_cmd" => ToolKind::Bash,
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "write" | "edit"
        | "str_replace" | "StrReplace" | "create_file" | "ApplyPatch" => ToolKind::FileWrite,
        _ => ToolKind::Unknown,
    }
}

fn first_str(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

/// Classify a Bash tool command string. Plain commands become a real argv so
/// policy can match argv0 and args; anything with shell syntax stays opaque.
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

fn emit(format: OutFormat, decision: &str, reason: &str) -> ExitCode {
    match format {
        OutFormat::ClaudeCode => {
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
        OutFormat::Codex => {
            // Codex lifecycle hooks: exit 2 blocks; stdout/stderr carry reason.
            eprintln!("{reason}");
            if decision == "deny" {
                ExitCode::from(2)
            } else {
                // allow and ask both exit 0 — ask defers to Codex's own prompt.
                ExitCode::SUCCESS
            }
        }
        OutFormat::Generic => {
            let out = serde_json::json!({
                "decision": decision,
                "reason": reason,
            });
            println!("{out}");
            if decision == "deny" {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
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
        assert_eq!(
            argv_of(command_to_op("git push origin main", ".")),
            vec!["git", "push", "origin", "main"]
        );
    }

    #[test]
    fn quoted_arguments_survive() {
        assert_eq!(
            argv_of(command_to_op("git commit -m \"fix the thing\"", ".")),
            vec!["git", "commit", "-m", "fix the thing"]
        );
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

    #[test]
    fn parses_codex_shaped_shell_tool() {
        let hook = serde_json::json!({
            "session_id": "s",
            "cwd": "/tmp",
            "tool_name": "shell",
            "tool_input": {"command": "ls"}
        });
        match parse_hook(&hook, "codex") {
            Parsed::Request(r) => assert_eq!(r.harness, "codex"),
            Parsed::Defer { reason } => panic!("unexpected defer: {reason}"),
        }
    }

    #[test]
    fn parses_generic_path_write() {
        let hook = serde_json::json!({
            "harness": "opencode",
            "path": "/tmp/x.rs",
            "cwd": "/tmp"
        });
        match parse_hook(&hook, "generic") {
            Parsed::Request(GateRequest {
                op: Operation::FileWrite { path },
                ..
            }) => assert_eq!(path, "/tmp/x.rs"),
            Parsed::Request(_) => panic!("expected file write"),
            Parsed::Defer { reason } => panic!("unexpected defer: {reason}"),
        }
    }
}
