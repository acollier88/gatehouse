mod audit;
mod ctl;
mod policy;
mod server;
mod state;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use gatehouse_proto::{paths, Tier};
use tokio::net::UnixListener;
use tracing::{info, warn};

use audit::Audit;
use policy::Policy;
use state::Shared;

#[derive(Parser)]
#[command(name = "gatehoused", about = "Gatehouse approval broker daemon")]
struct Args {
    /// Seconds a pending request waits for approval before being denied.
    #[arg(long, default_value_t = 300)]
    approval_timeout_secs: u64,
}

pub struct Ctx {
    pub policy: Policy,
    pub state: Shared,
    pub approval_timeout: Duration,
    audit: Mutex<Audit>,
}

impl Ctx {
    /// Audit failures are logged, never fatal: refusing to work because the
    /// log disk hiccuped would just teach users to disable the broker.
    pub fn audit(&self, digest: &str, summary: &str, tier: Tier, decision: &str, rule: &str) {
        if let Err(e) = self
            .audit
            .lock()
            .unwrap()
            .record(digest, summary, tier, decision, rule)
        {
            warn!("audit write failed: {e}");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();
    let args = Args::parse();

    let policy_path = paths::policy_path();
    if !policy_path.exists() {
        std::fs::create_dir_all(policy_path.parent().unwrap())?;
        std::fs::write(&policy_path, policy::DEFAULT_POLICY)?;
        info!("wrote default policy to {}", policy_path.display());
    }
    let policy = Policy::load(&policy_path)?;
    info!(
        "policy loaded: {} rules, default tier {}",
        policy.rules.len(),
        policy.default_tier
    );

    let agent_path = paths::agent_sock();
    let ctl_path = paths::ctl_sock();
    let run_dir = agent_path.parent().unwrap();
    std::fs::create_dir_all(run_dir)?;
    std::fs::set_permissions(run_dir, std::fs::Permissions::from_mode(0o700))?;
    let agent = bind(&agent_path)?;
    let ctl = bind(&ctl_path)?;
    info!("agent socket: {}", agent_path.display());
    info!("ctl socket:   {}", ctl_path.display());
    info!("audit log:    {}", paths::audit_path().display());

    let ctx = Arc::new(Ctx {
        policy,
        state: Shared::default(),
        approval_timeout: Duration::from_secs(args.approval_timeout_secs),
        audit: Mutex::new(Audit::open(&paths::audit_path())?),
    });

    let started = Instant::now();
    tokio::select! {
        _ = server::run(agent, ctx.clone()) => {}
        _ = ctl::run(ctl, ctx.clone(), started) => {}
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
        }
    }
    let _ = std::fs::remove_file(&agent_path);
    let _ = std::fs::remove_file(&ctl_path);
    Ok(())
}

fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
