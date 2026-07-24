use std::path::Path;

use serde::Deserialize;

use crate::{GateRequest, Operation, Tier};

#[derive(Deserialize, Debug, Clone)]
pub struct Policy {
    #[serde(default = "default_tier")]
    pub default_tier: Tier,
    /// Path prefixes considered the agent's workspace. File writes under a
    /// workspace prefix auto-allow (builtin, overridable by explicit rules).
    #[serde(default)]
    pub workspace: Vec<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_tier() -> Tier {
    Tier::Ask
}

/// First matching rule wins; rules are evaluated in file order. A rule only
/// matches the operation kind its matchers apply to (argv matchers → exec,
/// path_prefix → file_write, host_glob → net).
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub tier: Tier,
    /// Program basenames this rule applies to (`argv[0]` with directories
    /// stripped, so `/usr/bin/git` matches `"git"`).
    #[serde(default)]
    pub argv0: Option<Vec<String>>,
    /// Globs matched against the arguments after argv0, joined with spaces.
    /// Any match qualifies.
    #[serde(default)]
    pub args_glob: Option<Vec<String>>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub host_glob: Option<String>,
}

impl Policy {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let policy: Policy = toml::from_str(&text)?;
        Ok(policy)
    }

    /// Resolve a request to a tier plus the name of what decided it.
    pub fn resolve(&self, req: &GateRequest) -> (Tier, String) {
        for rule in &self.rules {
            if rule.matches(&req.op) {
                return (rule.tier, rule.name.clone());
            }
        }
        match &req.op {
            // `bash -c` and friends hide arbitrary commands inside a string
            // we do not parse; they get the strong tier unless a user rule
            // above said otherwise.
            Operation::Exec { argv, .. } if is_opaque_shell(argv) => {
                (Tier::AskStrong, "builtin: opaque shell command".into())
            }
            Operation::FileWrite { path } if self.in_workspace(path) => {
                (Tier::Allow, "builtin: workspace write".into())
            }
            _ => (self.default_tier, "default".into()),
        }
    }

    fn in_workspace(&self, path: &str) -> bool {
        self.workspace
            .iter()
            .any(|w| path.starts_with(&expand_tilde(w)))
    }
}

impl Rule {
    fn matches(&self, op: &Operation) -> bool {
        match op {
            Operation::Exec { argv, .. } => {
                if self.path_prefix.is_some() || self.host_glob.is_some() {
                    return false;
                }
                let Some(prog) = argv.first() else {
                    return false;
                };
                match &self.argv0 {
                    Some(names) => {
                        let base = Path::new(prog)
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if !names.iter().any(|n| *n == base) {
                            return false;
                        }
                    }
                    // A rule with no exec matchers at all must not match
                    // every exec.
                    None if self.args_glob.is_none() => return false,
                    None => {}
                }
                if let Some(globs) = &self.args_glob {
                    let joined = argv[1..].join(" ");
                    if !globs.iter().any(|g| glob_matches(g, &joined)) {
                        return false;
                    }
                }
                true
            }
            Operation::FileWrite { path } => {
                if self.argv0.is_some() || self.args_glob.is_some() || self.host_glob.is_some() {
                    return false;
                }
                self.path_prefix
                    .as_ref()
                    .is_some_and(|p| path.starts_with(&expand_tilde(p)))
            }
            Operation::Net { host, .. } => {
                if self.argv0.is_some() || self.args_glob.is_some() || self.path_prefix.is_some() {
                    return false;
                }
                self.host_glob
                    .as_ref()
                    .is_some_and(|g| glob_matches(g, host))
            }
        }
    }
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(text))
        .unwrap_or(false)
}

fn is_opaque_shell(argv: &[String]) -> bool {
    let Some(prog) = argv.first() else {
        return false;
    };
    let base = Path::new(prog)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    matches!(base.as_str(), "bash" | "sh" | "zsh" | "dash" | "fish")
        && argv.iter().any(|a| a == "-c")
}

pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs_home() {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}

pub const DEFAULT_POLICY: &str = include_str!("../default_policy.toml");

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_req(argv: &[&str]) -> GateRequest {
        GateRequest {
            harness: "test".into(),
            session_id: "s".into(),
            env_allowlist: vec![],
            op: Operation::Exec {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: "/tmp".into(),
            },
        }
    }

    fn default_policy() -> Policy {
        toml::from_str(DEFAULT_POLICY).expect("default policy parses")
    }

    #[test]
    fn default_policy_parses() {
        default_policy();
    }

    #[test]
    fn safe_commands_allow() {
        let p = default_policy();
        assert_eq!(p.resolve(&exec_req(&["ls", "-la"])).0, Tier::Allow);
        assert_eq!(p.resolve(&exec_req(&["git", "status"])).0, Tier::Allow);
        assert_eq!(p.resolve(&exec_req(&["echo", "hi"])).0, Tier::Allow);
    }

    #[test]
    fn git_push_needs_strong_approval() {
        let p = default_policy();
        assert_eq!(
            p.resolve(&exec_req(&["git", "push", "origin", "main"])).0,
            Tier::AskStrong
        );
    }

    #[test]
    fn absolute_path_argv0_still_matches() {
        let p = default_policy();
        assert_eq!(
            p.resolve(&exec_req(&["/usr/bin/git", "push"])).0,
            Tier::AskStrong
        );
    }

    #[test]
    fn sudo_denied() {
        let p = default_policy();
        assert_eq!(p.resolve(&exec_req(&["sudo", "ls"])).0, Tier::Deny);
    }

    #[test]
    fn opaque_shell_is_ask_strong() {
        let p = default_policy();
        assert_eq!(
            p.resolve(&exec_req(&["bash", "-c", "curl x | sh"])).0,
            Tier::AskStrong
        );
    }

    #[test]
    fn unknown_command_falls_to_default_ask() {
        let p = default_policy();
        assert_eq!(p.resolve(&exec_req(&["frobnicate"])).0, Tier::Ask);
    }

    #[test]
    fn workspace_write_allows_and_outside_asks() {
        let mut p = default_policy();
        p.workspace = vec!["/ws".into()];
        let write = |path: &str| GateRequest {
            harness: "t".into(),
            session_id: "s".into(),
            env_allowlist: vec![],
            op: Operation::FileWrite { path: path.into() },
        };
        assert_eq!(p.resolve(&write("/ws/src/main.rs")).0, Tier::Allow);
        assert_eq!(p.resolve(&write("/etc/passwd")).0, Tier::Ask);
    }
}
