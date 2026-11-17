use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{contain, GateRequest, Operation, Tier};

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
    /// How the broker runs approved commands (`[exec]` table).
    #[serde(default)]
    pub exec: ExecPolicy,
}

fn default_tier() -> Tier {
    Tier::Ask
}

/// Settings for broker-executed children.
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ExecPolicy {
    /// Trusted directories, in order, for resolving a bare program name
    /// (`ls`, `git`). Used both to decide whether an absolute `argv[0]`
    /// is "the" `ls` an allow rule means, and as the `PATH` the broker runs
    /// the child with. Deliberately *not* the daemon's inherited `PATH`,
    /// which may contain relative or user-writable entries. Entries must be
    /// absolute (`~/` is expanded); others are ignored.
    pub path: Vec<String>,
}

impl Default for ExecPolicy {
    fn default() -> Self {
        Self {
            path: default_exec_path(),
        }
    }
}

fn default_exec_path() -> Vec<String> {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        vec![format!(r"{root}\System32"), root]
    }
    #[cfg(not(windows))]
    {
        let mut p: Vec<String> = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if cfg!(target_os = "macos") {
            p.push("/opt/homebrew/bin".into());
        }
        p
    }
}

/// First matching rule wins; rules are evaluated in file order. A rule only
/// matches the operation kind its matchers apply to (argv matchers → exec,
/// path_prefix → file_write, host_glob → net).
///
/// Permissive (`allow`) rules match *strictly* and restrictive ones
/// (`ask`/`ask_strong`/`deny`) match *loosely*, so that an unusual spelling
/// of a request can only ever fall through to a more cautious tier:
/// `/tmp/x/ls` is not the `ls` of an allow rule, but `/tmp/x/git push` is
/// still the `git` of the ask-strong push rule.
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub tier: Tier,
    /// Program names this rule applies to. For restrictive tiers, matched
    /// against the basename of `argv[0]`. For `allow`, `argv[0]` must be the
    /// bare name, or an absolute path to that same file in a trusted
    /// `[exec] path` directory; `./ls` or `/tmp/x/ls` never match.
    #[serde(default)]
    pub argv0: Option<Vec<String>>,
    /// Globs matched against the arguments after argv0, joined with spaces.
    /// Any match qualifies. (Joining means one argument containing spaces
    /// can look like several; use the per-argument matchers below when
    /// that matters. For allow rules the first argument may not contain
    /// whitespace, so the subcommand position cannot be spoofed.)
    #[serde(default)]
    pub args_glob: Option<Vec<String>>,
    /// Per-argument globs: the rule needs at least one single argument
    /// matching one of these. Use for restrictive rules ("any `-r` flag,
    /// wherever it appears").
    #[serde(default)]
    pub args_any_glob: Option<Vec<String>>,
    /// Per-argument globs: the rule does *not* match if any single argument
    /// matches one of these. Use to carve dangerous options out of allow
    /// rules (`find -exec`, `rg --pre`). On its own it is not an exec
    /// matcher — it only narrows a rule that has `argv0` or an args glob.
    #[serde(default)]
    pub args_deny_glob: Option<Vec<String>>,
    /// Require the request's `cwd` to be inside a `workspace` root and every
    /// argument that could be a path (each plain argument, and the value of
    /// `--opt=value`) to resolve inside a workspace root. Arguments starting
    /// with `~`, and short options with an attached path (`-f/etc/x`), never
    /// qualify. With no workspace configured, such a rule never matches.
    #[serde(default)]
    pub args_in_workspace: bool,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub host_glob: Option<String>,
}

impl Policy {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let policy: Policy = toml::from_str(&text)?;
        for p in &policy.exec.path {
            if !Path::new(&expand_tilde(p)).is_absolute() {
                anyhow::bail!("[exec] path entry {p:?} is not absolute");
            }
        }
        Ok(policy)
    }

    /// Resolve a request to a tier plus the name of what decided it.
    pub fn resolve(&self, req: &GateRequest) -> (Tier, String) {
        for rule in &self.rules {
            if rule.matches(self, &req.op) {
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

    /// Strict containment (see [`crate::contain`]): absolute, lexically
    /// inside a workspace root, and still inside once existing symlinks are
    /// resolved. A relative path is never "in the workspace" — `FileWrite`
    /// carries no cwd to resolve it against.
    pub fn in_workspace(&self, path: &str) -> bool {
        self.workspace
            .iter()
            .any(|w| contain::within_strict(path, &expand_tilde(w)))
    }

    /// The trusted search path, absolute entries only.
    pub fn exec_path(&self) -> Vec<PathBuf> {
        self.exec
            .path
            .iter()
            .map(|p| PathBuf::from(expand_tilde(p)))
            .filter(|p| p.is_absolute())
            .collect()
    }

    /// The file the broker should execute for `argv[0]`:
    /// - a bare name is looked up in the trusted `[exec] path` only — never
    ///   the daemon's `PATH`, never the request cwd;
    /// - an absolute path is used as given;
    /// - a relative path with a separator (`./build.sh`) is joined onto the
    ///   request cwd explicitly, so it never depends on the daemon's cwd.
    ///
    /// `None` if a bare name is not found, or a relative program has no
    /// absolute cwd to anchor it.
    pub fn resolve_program(&self, prog: &str, cwd: &str) -> Option<PathBuf> {
        if is_bare_name(prog) {
            return lookup_trusted(prog, &self.exec_path());
        }
        let p = Path::new(prog);
        if p.is_absolute() {
            return Some(p.to_path_buf());
        }
        let cwd = Path::new(cwd);
        if !cwd.is_absolute() {
            return None;
        }
        contain::normalize_lexical(&cwd.join(p))
    }

    /// The program name an allow rule may match `argv[0]` as, or `None` if
    /// `argv[0]` is not a trusted spelling of any program.
    fn trusted_program_name<'a>(&self, prog: &'a str) -> Option<&'a str> {
        if is_bare_name(prog) {
            return Some(prog);
        }
        let p = Path::new(prog);
        if !p.is_absolute() {
            return None;
        }
        let name = p.file_name()?.to_str()?;
        let real = std::fs::canonicalize(p).ok()?;
        self.exec_path()
            .iter()
            .filter_map(|dir| executable_in(dir, name))
            .any(|cand| std::fs::canonicalize(cand).is_ok_and(|c| c == real))
            .then_some(name)
    }
}

/// `prog` names a program without any directory part.
fn is_bare_name(prog: &str) -> bool {
    if prog.is_empty() || prog == "." || prog == ".." || prog.contains('/') {
        return false;
    }
    !(cfg!(windows) && (prog.contains('\\') || prog.contains(':')))
}

fn lookup_trusted(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter().find_map(|d| executable_in(d, name))
}

/// `dir/name` if it is an executable regular file (following symlinks).
fn executable_in(dir: &Path, name: &str) -> Option<PathBuf> {
    #[cfg(not(unix))]
    {
        let mut cands = vec![dir.join(name)];
        if Path::new(name).extension().is_none() {
            cands.push(dir.join(format!("{name}.exe")));
            cands.push(dir.join(format!("{name}.com")));
        }
        cands
            .into_iter()
            .find(|c| std::fs::metadata(c).is_ok_and(|m| m.is_file()))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let c = dir.join(name);
        let m = std::fs::metadata(&c).ok()?;
        (m.is_file() && m.permissions().mode() & 0o111 != 0).then_some(c)
    }
}

impl Rule {
    fn has_exec_matcher(&self) -> bool {
        self.argv0.is_some() || self.args_glob.is_some() || self.args_any_glob.is_some()
    }

    fn has_exec_fields(&self) -> bool {
        self.has_exec_matcher() || self.args_deny_glob.is_some() || self.args_in_workspace
    }

    fn matches(&self, policy: &Policy, op: &Operation) -> bool {
        match op {
            Operation::Exec { argv, cwd } => {
                if self.path_prefix.is_some() || self.host_glob.is_some() {
                    return false;
                }
                // A rule with no exec matchers at all must not match every
                // exec.
                if !self.has_exec_matcher() {
                    return false;
                }
                let Some(prog) = argv.first() else {
                    return false;
                };
                let args = &argv[1..];
                if let Some(names) = &self.argv0 {
                    let name = if self.tier == Tier::Allow {
                        policy.trusted_program_name(prog)
                    } else {
                        Path::new(prog).file_name().and_then(|s| s.to_str())
                    };
                    if !name.is_some_and(|n| names.iter().any(|x| x == n)) {
                        return false;
                    }
                }
                if let Some(globs) = &self.args_glob {
                    // Joining loses argument boundaries. For allow rules keep
                    // the subcommand position unambiguous: `["status x"]`
                    // must not pass for `status *`.
                    if self.tier == Tier::Allow
                        && args
                            .first()
                            .is_some_and(|a| a.contains(char::is_whitespace))
                    {
                        return false;
                    }
                    let joined = args.join(" ");
                    if !globs.iter().any(|g| glob_matches(g, &joined)) {
                        return false;
                    }
                }
                if let Some(globs) = &self.args_any_glob {
                    if !args
                        .iter()
                        .any(|a| globs.iter().any(|g| glob_matches(g, a)))
                    {
                        return false;
                    }
                }
                if let Some(globs) = &self.args_deny_glob {
                    if args
                        .iter()
                        .any(|a| globs.iter().any(|g| glob_matches(g, a)))
                    {
                        return false;
                    }
                }
                if self.args_in_workspace && !args_in_workspace(policy, cwd, args) {
                    return false;
                }
                true
            }
            Operation::FileWrite { path } => {
                if self.has_exec_fields() || self.host_glob.is_some() {
                    return false;
                }
                // Permissive rules need the path certainly inside the
                // prefix; restrictive ones fire if it could be inside.
                self.path_prefix.as_ref().is_some_and(|p| {
                    let root = expand_tilde(p);
                    if self.tier == Tier::Allow {
                        contain::within_strict(path, &root)
                    } else {
                        contain::within_loose(path, &root)
                    }
                })
            }
            Operation::Net { host, .. } => {
                if self.has_exec_fields() || self.path_prefix.is_some() {
                    return false;
                }
                self.host_glob
                    .as_ref()
                    .is_some_and(|g| glob_matches(g, host))
            }
        }
    }
}

/// See [`Rule::args_in_workspace`].
fn args_in_workspace(policy: &Policy, cwd: &str, args: &[String]) -> bool {
    let roots: Vec<String> = policy.workspace.iter().map(|w| expand_tilde(w)).collect();
    let inside = |p: &str| roots.iter().any(|r| contain::within_strict(p, r));
    if roots.is_empty() || !inside(cwd) {
        return false;
    }
    args.iter().all(|arg| {
        let candidate = if arg.starts_with('-') {
            match arg.split_once('=') {
                Some((_, "")) => return true,
                Some((_, value)) => value,
                // A bare flag or a short-option cluster. An attached value
                // (`-f/etc/x`, `-O~/x`) cannot be told apart from flags, so
                // anything path-shaped in one fails closed.
                None => {
                    return !(arg.contains(['/', '\\', '~']) || arg.contains(".."));
                }
            }
        } else {
            arg.as_str()
        };
        if candidate.starts_with('~') {
            return false;
        }
        let full = Path::new(cwd).join(candidate);
        full.to_str().is_some_and(inside)
    })
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
    // `-c` may be clustered with other flags (`bash -ec '...'`).
    matches!(
        base.as_str(),
        "bash" | "sh" | "zsh" | "dash" | "fish" | "ksh" | "mksh"
    ) && argv[1..]
        .iter()
        .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
}

pub fn expand_tilde(path: &str) -> String {
    let home = || {
        std::env::var("HOME")
            .ok()
            .or_else(|| dirs::home_dir().map(|h| h.to_string_lossy().into_owned()))
    };
    if path == "~" {
        if let Some(home) = home() {
            return home;
        }
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home() {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
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

    fn write_req(path: &str) -> GateRequest {
        GateRequest {
            harness: "t".into(),
            session_id: "s".into(),
            env_allowlist: vec![],
            op: Operation::FileWrite { path: path.into() },
        }
    }

    /// Regressions: the workspace check was a raw string prefix.
    #[test]
    fn workspace_rejects_traversal_sibling_and_relative() {
        let mut p = default_policy();
        p.workspace = vec!["/ws".into()];
        for path in [
            "/ws/../etc/passwd",
            "/ws-evil/x",
            "src/main.rs",
            "../ws/x",
            "",
        ] {
            assert_eq!(p.resolve(&write_req(path)).0, Tier::Ask, "{path}");
        }
    }

    #[test]
    fn path_prefix_rules_are_component_wise_and_tier_aware() {
        let p: Policy = toml::from_str(
            r#"
            [[rules]]
            name = "ssh keys denied"
            tier = "deny"
            path_prefix = "/home/u/.ssh"

            [[rules]]
            name = "build dir allowed"
            tier = "allow"
            path_prefix = "/ws/target"
            "#,
        )
        .unwrap();
        let t = |path: &str| p.resolve(&write_req(path)).0;
        assert_eq!(t("/home/u/.ssh/authorized_keys"), Tier::Deny);
        assert_eq!(t("/home/u/x/../.ssh/authorized_keys"), Tier::Deny);
        assert_eq!(t("/home/u/.sshx"), Tier::Ask);
        // Unknown location: matches the restrictive rule, not the permissive.
        assert_eq!(t("authorized_keys"), Tier::Deny);
        assert_eq!(t("/ws/target-evil/x"), Tier::Ask);
        assert_eq!(t("/ws/target/../../etc/x"), Tier::Ask);
    }

    // --- allow tier hardening (argv0 resolution, defaults) -----------------

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "gh-policy-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn plant_executable(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, b"#!/bin/sh\necho pwned\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Default policy with a real temp dir as workspace; returns (policy, ws).
    fn ws_policy() -> (Policy, String) {
        let ws = tempdir("ws");
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(ws.join("src/main.rs"), b"fn main() {}").unwrap();
        let mut p = default_policy();
        let ws = ws.to_string_lossy().into_owned();
        p.workspace = vec![ws.clone()];
        (p, ws)
    }

    fn exec_in(cwd: &str, argv: &[&str]) -> GateRequest {
        let mut r = exec_req(argv);
        if let Operation::Exec { cwd: c, .. } = &mut r.op {
            *c = cwd.into();
        }
        r
    }

    /// Regression: the broker runs allowed commands itself, and argv0 used
    /// to match by basename, so `./ls` ran whatever the requester had put
    /// in the cwd under the "read-only basics" allow rule.
    #[cfg(unix)]
    #[test]
    fn allow_rules_need_a_trusted_argv0() {
        let p = default_policy();
        let evil = tempdir("evil");
        let planted = plant_executable(&evil, "ls");
        let planted = planted.to_str().unwrap();
        let cwd = evil.to_str().unwrap();
        for prog in ["./ls", planted, "bin/ls", "../ls"] {
            assert_ne!(
                p.resolve(&exec_in(cwd, &[prog, "-la"])).0,
                Tier::Allow,
                "{prog}"
            );
        }
        // The real one, spelled absolutely, still matches.
        if let Some(real) = p.resolve_program("ls", "/") {
            let real = real.to_str().unwrap();
            assert_eq!(p.resolve(&exec_req(&[real, "-la"])).0, Tier::Allow);
        }
    }

    /// Restrictive rules keep matching odd spellings.
    #[test]
    fn restrictive_rules_still_match_by_basename() {
        let p = default_policy();
        assert_eq!(p.resolve(&exec_req(&["/tmp/x/sudo", "ls"])).0, Tier::Deny);
        assert_eq!(p.resolve(&exec_req(&["./git", "push"])).0, Tier::AskStrong);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_program_never_uses_cwd_or_daemon_path() {
        let trusted = tempdir("trusted");
        let real = plant_executable(&trusted, "frob");
        let cwd = tempdir("cwd");
        plant_executable(&cwd, "frob");
        let mut p = default_policy();
        p.exec.path = vec![trusted.to_string_lossy().into_owned()];
        let cwd = cwd.to_str().unwrap();
        assert_eq!(p.resolve_program("frob", cwd), Some(real));
        assert_eq!(p.resolve_program("nope-not-here", cwd), None);
        assert_eq!(
            p.resolve_program("./build.sh", "/ws/proj"),
            Some(PathBuf::from("/ws/proj/build.sh"))
        );
        assert_eq!(p.resolve_program("./build.sh", "."), None);
        // Relative entries in [exec] path are ignored.
        p.exec.path = vec![".".into(), "bin".into()];
        assert!(p.exec_path().is_empty());
        assert_eq!(p.resolve_program("frob", cwd), None);
    }

    #[test]
    fn find_exec_and_friends_are_not_allowed() {
        let (p, ws) = ws_policy();
        let t = |argv: &[&str]| p.resolve(&exec_in(&ws, argv)).0;
        assert_eq!(t(&["find", ".", "-name", "*.rs"]), Tier::Allow);
        for bad in [
            &["find", ".", "-exec", "sh", "-c", "id", ";"][..],
            &["find", ".", "-execdir", "id", ";"],
            &["find", ".", "-ok", "id", ";"],
            &["find", ".", "-delete"],
            &["find", ".", "-fprint", "out"],
            &["find", "-L", "."],
            &["find", "/", "-name", "id_rsa"],
        ] {
            assert_ne!(t(bad), Tier::Allow, "{bad:?}");
        }
    }

    #[test]
    fn git_fetch_and_option_abuse_are_not_allowed() {
        let (p, ws) = ws_policy();
        let t = |argv: &[&str]| p.resolve(&exec_in(&ws, argv)).0;
        assert_eq!(t(&["git", "status"]), Tier::Allow);
        assert_eq!(t(&["git", "log", "--oneline", "-5"]), Tier::Allow);
        assert_eq!(t(&["git", "diff", "HEAD~1", "--", "src"]), Tier::Allow);
        assert_eq!(t(&["git", "show", "HEAD:src/main.rs"]), Tier::Allow);
        for bad in [
            &["git", "fetch", "--upload-pack=touch /tmp/pwned", "origin"][..],
            &[
                "git",
                "fetch",
                "--upload-pack",
                "touch /tmp/pwned",
                "origin",
            ],
            &["git", "fetch", "origin"],
            &["git", "diff", "--output=/tmp/x"],
            &["git", "diff", "--output=inside.txt"],
            &["git", "log", "--out=inside.txt"],
            &["git", "show", "--output", "x"],
            &["git", "diff", "--no-index", "/etc/passwd", "/dev/null"],
            &["git", "diff", "/etc/passwd"],
            &["git", "-c", "core.pager=sh", "log"],
            &["git", "-C", "/", "log"],
            &["git", "difftool", "--extcmd=sh"],
            &["git", "statusx"],
            &["git", "logx"],
            &["git", "branch", "-v", "-D", "main"],
            // One argument with a space must not pass for two.
            &["git", "status -s"],
        ] {
            assert_ne!(t(bad), Tier::Allow, "{bad:?}");
        }
        // Reading history is confined to the workspace.
        assert_eq!(p.resolve(&exec_in("/", &["git", "log"])).0, Tier::Ask);
    }

    #[test]
    fn rg_and_grep_dangerous_options_are_not_allowed() {
        let (p, ws) = ws_policy();
        let t = |argv: &[&str]| p.resolve(&exec_in(&ws, argv)).0;
        assert_eq!(t(&["rg", "-n", "main", "src"]), Tier::Allow);
        assert_eq!(t(&["grep", "-rn", "main", "."]), Tier::Allow);
        for bad in [
            &["rg", "--pre", "sh", "x"][..],
            &["rg", "--pre=sh", "x"],
            &["rg", "-L", "x"],
            &["rg", "-iL", "x"],
            &["grep", "-R", "x", "."],
            &["grep", "-f/etc/shadow", "x"],
            &["grep", "--file=/etc/shadow", "x"],
            &["grep", "root", "/etc/passwd"],
        ] {
            assert_ne!(t(bad), Tier::Allow, "{bad:?}");
        }
    }

    /// Regression: `cat` of any path was auto-allowed.
    #[test]
    fn cat_is_confined_to_the_workspace() {
        let (p, ws) = ws_policy();
        let t = |cwd: &str, argv: &[&str]| p.resolve(&exec_in(cwd, argv)).0;
        assert_eq!(t(&ws, &["cat", "src/main.rs"]), Tier::Allow);
        assert_eq!(t(&ws, &["head", "-n", "5", "src/main.rs"]), Tier::Allow);
        for bad in [
            &["cat", "/etc/passwd"][..],
            &["cat", "~/.ssh/id_rsa"],
            &["cat", "../../etc/passwd"],
            &["cat", "src/../../x"],
            &["tail", "-n5", "/etc/passwd"],
        ] {
            assert_ne!(t(&ws, bad), Tier::Allow, "{bad:?}");
        }
        // cwd is requester-chosen, so it must itself be in the workspace.
        assert_ne!(t("/etc", &["cat", "passwd"]), Tier::Allow);
        assert_ne!(t(".", &["cat", "x"]), Tier::Allow);
        // No workspace configured: never auto-allowed.
        let bare = default_policy();
        assert_ne!(
            bare.resolve(&exec_in(&ws, &["cat", "src/main.rs"])).0,
            Tier::Allow
        );
    }

    #[cfg(unix)]
    #[test]
    fn cat_through_an_escaping_symlink_is_not_allowed() {
        let (p, ws) = ws_policy();
        let out = tempdir("out");
        std::fs::write(out.join("secret"), b"x").unwrap();
        std::os::unix::fs::symlink(out.join("secret"), Path::new(&ws).join("link")).unwrap();
        assert_ne!(p.resolve(&exec_in(&ws, &["cat", "link"])).0, Tier::Allow);
    }

    #[test]
    fn push_and_rm_are_caught_wherever_the_flag_sits() {
        let p = default_policy();
        let t = |argv: &[&str]| p.resolve(&exec_req(argv)).0;
        assert_eq!(t(&["git", "-C", "/repo", "push"]), Tier::AskStrong);
        assert_eq!(t(&["git", "-c", "a=b", "push", "--force"]), Tier::AskStrong);
        for rm in [
            &["rm", "-rf", "x"][..],
            &["rm", "x", "-r"],
            &["rm", "-v", "-f", "x"],
            &["rm", "-vR", "x"],
            &["rm", "--recursive", "x"],
            &["rm", "--rec", "x"],
            &["rm", "--force", "x"],
            &["rm", "--no-preserve-root", "-v", "/"],
        ] {
            assert_eq!(t(rm), Tier::AskStrong, "{rm:?}");
        }
        assert_eq!(t(&["rm", "x"]), Tier::Ask);
        assert_eq!(t(&["rm", "-i", "x"]), Tier::Ask);
    }

    #[test]
    fn clustered_shell_c_is_opaque() {
        let p = default_policy();
        for argv in [
            &["bash", "-ec", "id"][..],
            &["sh", "-xc", "id"],
            &["/bin/zsh", "-c", "id"],
        ] {
            assert_eq!(p.resolve(&exec_req(argv)).0, Tier::AskStrong, "{argv:?}");
        }
    }

    #[test]
    fn old_policy_files_still_parse_and_match() {
        let p: Policy = toml::from_str(
            r#"
            default_tier = "ask"
            [[rules]]
            name = "npm scripts"
            tier = "allow"
            argv0 = ["npm"]
            args_glob = ["run test*"]
            "#,
        )
        .unwrap();
        assert_eq!(p.resolve(&exec_req(&["npm", "run", "test"])).0, Tier::Allow);
        assert_eq!(p.resolve(&exec_req(&["npm", "install"])).0, Tier::Ask);
        assert!(!p.exec_path().is_empty());
    }

    #[test]
    fn deny_glob_alone_is_not_an_exec_matcher() {
        let p: Policy = toml::from_str(
            r#"
            [[rules]]
            name = "oops"
            tier = "allow"
            args_deny_glob = ["--evil"]
            "#,
        )
        .unwrap();
        assert_eq!(p.resolve(&exec_req(&["anything"])).0, Tier::Ask);
    }
}
