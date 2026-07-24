mod audit;
mod certs;
mod ctl;
mod phone;
mod policy;
mod relay;
mod relay_client;
mod server;
mod state;
mod web;

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use gatehouse_proto::{paths, Tier};
use tokio::net::UnixListener;
use tracing::{info, warn};
use webauthn_rs::prelude::Passkey;

use audit::Audit;
use phone::load_phone_passkeys;
use policy::Policy;
use state::Shared;

#[derive(Parser)]
#[command(name = "gatehoused", about = "Gatehouse approval broker daemon")]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Seconds a pending request waits for approval before being denied.
    #[arg(long, default_value_t = 300, global = true)]
    approval_timeout_secs: u64,
    /// Don't auto-open the approval page when an ask-strong request arrives.
    #[arg(long, global = true)]
    no_open: bool,
    /// Dial out to a phone approval relay (wss/https URL of the daemon mTLS port).
    #[arg(long, global = true)]
    relay_url: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate mTLS certs + phone token for the approval relay.
    RelayInit {
        /// WebAuthn RP ID (usually the hostname phones will see).
        #[arg(long)]
        rp_id: String,
        /// Public origin phones use, e.g. https://box.tailnet.ts.net:8787
        #[arg(long)]
        origin: String,
        /// Phone HTTPS listen address stored in config (default 0.0.0.0:8787).
        #[arg(long, default_value = "0.0.0.0:8787")]
        listen: String,
        /// Daemon mTLS listen address stored in config (default 0.0.0.0:8788).
        #[arg(long, default_value = "0.0.0.0:8788")]
        daemon_listen: String,
        /// Overwrite existing material.
        #[arg(long)]
        force: bool,
    },
    /// Run the phone approval relay (PWA + mTLS daemon port).
    Relay {
        #[arg(long, default_value = "0.0.0.0:8787")]
        listen: String,
        #[arg(long, default_value = "0.0.0.0:8788")]
        daemon_listen: String,
    },
}

pub struct Ctx {
    pub policy: Policy,
    pub state: Shared,
    pub approval_timeout: Duration,
    pub passkeys: Mutex<Vec<Passkey>>,
    pub phone_passkeys: Mutex<Vec<Passkey>>,
    pub http: OnceLock<web::HttpInfo>,
    /// Phone console URL when a relay is configured (`origin/?t=token`).
    pub phone_url: OnceLock<String>,
    pub auto_open: bool,
    audit: Mutex<Audit>,
}

impl Ctx {
    pub fn passkeys_enrolled(&self) -> bool {
        !self.passkeys.lock().unwrap().is_empty()
            || !self.phone_passkeys.lock().unwrap().is_empty()
    }

    /// Prefer the phone relay URL when available; else localhost page.
    pub fn approval_url(&self) -> Option<String> {
        if let Some(u) = self.phone_url.get() {
            return Some(u.clone());
        }
        self.http.get().map(|i| web::page_url(i.port, &i.token))
    }
}

fn load_passkeys() -> Vec<Passkey> {
    std::fs::read_to_string(paths::passkeys_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

pub fn save_passkeys(keys: &[Passkey]) {
    let path = paths::passkeys_path();
    let write = || -> anyhow::Result<()> {
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, serde_json::to_string_pretty(keys)?)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    };
    if let Err(e) = write() {
        warn!("failed to persist passkeys: {e}");
    }
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
    // rustls 0.23 requires an explicit process-wide provider when more than
    // one backend is linked (ring via us, aws-lc via transitive deps).
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();
    let args = Args::parse();

    match args.cmd {
        Some(Cmd::RelayInit {
            rp_id,
            origin,
            listen,
            daemon_listen,
            force,
        }) => {
            certs::RelayMaterial::init(&rp_id, &origin, &listen, &daemon_listen, force)?;
            Ok(())
        }
        Some(Cmd::Relay {
            listen,
            daemon_listen,
        }) => {
            let listen: SocketAddr = listen.parse()?;
            let daemon_listen: SocketAddr = daemon_listen.parse()?;
            relay::run(listen, daemon_listen).await
        }
        None => run_daemon(args).await,
    }
}

async fn run_daemon(args: Args) -> anyhow::Result<()> {
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

    let passkeys = load_passkeys();
    let phone_passkeys = load_phone_passkeys();
    info!(
        "passkeys enrolled: local={} phone={}",
        passkeys.len(),
        phone_passkeys.len()
    );
    let ctx = Arc::new(Ctx {
        policy,
        state: Shared::default(),
        approval_timeout: Duration::from_secs(args.approval_timeout_secs),
        passkeys: Mutex::new(passkeys),
        phone_passkeys: Mutex::new(phone_passkeys),
        http: OnceLock::new(),
        phone_url: OnceLock::new(),
        auto_open: !args.no_open,
        audit: Mutex::new(Audit::open(&paths::audit_path())?),
    });

    let started = Instant::now();
    let relay_url = args.relay_url.clone();
    tokio::select! {
        _ = server::run(agent, ctx.clone()) => {}
        _ = ctl::run(ctl, ctx.clone(), started) => {}
        r = web::run(ctx.clone()) => {
            if let Err(e) = r {
                warn!("web server exited: {e}");
            }
        }
        r = async {
            if let Some(url) = relay_url {
                relay_client::run(ctx.clone(), &url).await
            } else {
                std::future::pending::<anyhow::Result<()>>().await
            }
        } => {
            if let Err(e) = r {
                warn!("relay client exited: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
        }
    }
    let _ = std::fs::remove_file(paths::http_info_path());
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
