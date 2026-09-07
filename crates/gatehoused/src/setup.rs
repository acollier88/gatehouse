//! Interactive / Tailscale-aware relay bootstrap.
//!
//! `relay-init` can detect a Tailscale MagicDNS name, ask whether to use it,
//! or take an explicit custom / hosted origin. Re-running with `--force`
//! updates the published URLs (and regenerates certs); phone passkeys must
//! be re-enrolled when the RP ID changes.

use std::io::{self, BufRead, Write};
use std::process::Command;

use anyhow::{bail, Context};
use gatehouse_proto::paths;
use tracing::info;

use crate::certs::{MaterialSpec, RelayMaterial};

pub struct InitOpts {
    pub rp_id: Option<String>,
    pub origin: Option<String>,
    pub listen: String,
    pub daemon_listen: String,
    pub phone_port: u16,
    pub daemon_port: u16,
    /// Prefer Tailscale MagicDNS when resolving missing rp_id/origin.
    pub tailscale: bool,
    /// Hosted / integrator mode: token daemon auth (no shared CA copy).
    pub hosted: bool,
    /// Override daemon auth: `mtls`, `token`, or `both`.
    pub daemon_auth: Option<String>,
    pub force: bool,
    /// Keep the existing phone bearer token across --force re-setup.
    pub keep_token: bool,
    /// Skip prompts (CI / scripts).
    pub yes: bool,
}

pub fn run_relay_init(opts: InitOpts) -> anyhow::Result<()> {
    let cfg_path = paths::relay_config_path();
    if cfg_path.exists() && !opts.force {
        if let Ok(existing) = RelayMaterial::load() {
            println!("relay already configured:");
            println!("  rp_id:  {}", existing.config.rp_id);
            println!("  origin: {}", existing.config.origin);
            println!("  phone:  {}", existing.phone_url());
            println!();
            println!("Re-run with --force to change the hostname/URLs.");
            println!("Tip: gatehoused relay-init --tailscale --force");
            println!("(Changing rp_id invalidates phone passkeys — re-enroll after.)");
            return Ok(());
        }
    }

    let (rp_id, origin, transport) = resolve_endpoints(&opts)?;
    let daemon_auth = opts
        .daemon_auth
        .clone()
        .or_else(|| {
            if opts.hosted || transport == "hosted" {
                Some("token".into())
            } else {
                Some("mtls".into())
            }
        });
    let keep = if opts.keep_token {
        RelayMaterial::load().ok().map(|m| m.config.phone_token)
    } else {
        None
    };

    if opts.force && cfg_path.exists() {
        if let Ok(old) = RelayMaterial::load() {
            if old.config.rp_id != rp_id {
                println!(
                    "warning: rp_id changing {} → {}; re-enroll phone passkeys after this",
                    old.config.rp_id, rp_id
                );
            }
        }
    }

    let material = RelayMaterial::init(MaterialSpec {
        rp_id: &rp_id,
        origin: &origin,
        listen: &opts.listen,
        daemon_listen: &opts.daemon_listen,
        force: opts.force,
        keep_token: keep,
        transport: Some(transport.clone()),
        daemon_auth: daemon_auth.clone(),
    })?;
    println!();
    println!("transport:   {transport}");
    println!("daemon_auth: {}", daemon_auth.as_deref().unwrap_or("mtls"));
    println!("phone URL:   {}", material.phone_url());
    if daemon_auth.as_deref() == Some("token") {
        println!("daemon:      enroll with: gatehoused device-enroll --label laptop --write \\");
        println!(
            "                --endpoint https://{rp_id}:{}",
            opts.phone_port
        );
        println!(
            "relay:       gatehoused relay --listen {} --daemon-listen {}",
            opts.listen, opts.daemon_listen
        );
        println!("             (token WS is on the phone port /ws)");
    } else {
        println!(
            "daemon:      gatehoused --relay-url https://{rp_id}:{} --no-open",
            opts.daemon_port
        );
        println!(
            "relay:       gatehoused relay --listen {} --daemon-listen {}",
            opts.listen, opts.daemon_listen
        );
    }
    Ok(())
}

pub fn show_relay() -> anyhow::Result<()> {
    let m = RelayMaterial::load()?;
    println!("rp_id:       {}", m.config.rp_id);
    println!("origin:      {}", m.config.origin);
    if let Some(t) = &m.config.transport {
        println!("transport:   {t}");
    }
    println!("daemon_auth: {}", m.daemon_auth());
    println!("phone URL:   {}", m.phone_url());
    println!("listen:      {}", m.config.listen);
    println!("daemon:      {}", m.config.daemon_listen);
    let n = crate::devices::load_devices().map(|d| d.len()).unwrap_or(0);
    println!("devices:     {n}");
    Ok(())
}

fn resolve_endpoints(opts: &InitOpts) -> anyhow::Result<(String, String, String)> {
    if let (Some(rp), Some(origin)) = (&opts.rp_id, &opts.origin) {
        let transport = if opts.hosted {
            "hosted"
        } else if opts.tailscale || looks_like_tailscale(rp) {
            "tailscale"
        } else if origin.contains("localhost") {
            "localhost"
        } else {
            "custom"
        };
        return Ok((rp.clone(), origin.trim_end_matches('/').to_string(), transport.into()));
    }

    let ts = detect_tailscale_dns();
    if opts.tailscale {
        let host = ts.context("tailscale status failed — is Tailscale installed and logged in?")?;
        return Ok(endpoints_for_host(&host, opts.phone_port, "tailscale"));
    }

    if let Some(rp) = &opts.rp_id {
        let origin = opts
            .origin
            .clone()
            .unwrap_or_else(|| format!("https://{rp}:{}", opts.phone_port));
        let transport = if opts.hosted {
            "hosted"
        } else if looks_like_tailscale(rp) {
            "tailscale"
        } else {
            "custom"
        };
        return Ok((rp.clone(), origin.trim_end_matches('/').to_string(), transport.into()));
    }

    // Interactive / guided path.
    if opts.yes {
        bail!("missing --rp-id/--origin (or pass --tailscale); refused to prompt because --yes");
    }
    if !stdin_is_tty() {
        bail!(
            "missing --rp-id and --origin. Examples:\n  \
             gatehoused relay-init --tailscale\n  \
             gatehoused relay-init --rp-id host.example.com --origin https://host.example.com:8787"
        );
    }

    println!("Gatehouse phone relay setup");
    println!("Passkeys bind to a hostname (WebAuthn RP ID). Pick how phones will reach this machine.\n");

    if let Some(host) = &ts {
        println!("Detected Tailscale MagicDNS: {host}");
        print!("Use Tailscale for phone approvals? [Y/n/custom]: ");
        io::stdout().flush()?;
        let answer = read_line()?.to_lowercase();
        if answer.is_empty() || answer == "y" || answer == "yes" {
            return Ok(endpoints_for_host(host, opts.phone_port, "tailscale"));
        }
        // n / custom / anything else → ask for explicit host below
    } else {
        println!(
            "Tailscale not detected (optional). You can still use a VPS hostname \
             or a future hosted relay URL."
        );
    }

    print!("Hostname phones will open (RP ID), or full https:// origin: ");
    io::stdout().flush()?;
    let line = read_line()?;
    if line.is_empty() {
        bail!("hostname/origin required");
    }
    if line.starts_with("https://") || line.starts_with("http://") {
        let origin = line.trim_end_matches('/').to_string();
        let host = host_from_origin(&origin)?;
        let transport = if looks_like_tailscale(&host) {
            "tailscale"
        } else if host == "localhost" {
            "localhost"
        } else {
            "custom"
        };
        return Ok((host, origin, transport.into()));
    }
    let transport = if looks_like_tailscale(&line) {
        "tailscale"
    } else {
        "custom"
    };
    Ok(endpoints_for_host(&line, opts.phone_port, transport))
}

fn endpoints_for_host(host: &str, phone_port: u16, transport: &str) -> (String, String, String) {
    let host = host.trim_end_matches('.').to_string();
    let origin = format!("https://{host}:{phone_port}");
    (host, origin, transport.to_string())
}

fn looks_like_tailscale(host: &str) -> bool {
    host.contains(".ts.net") || host.ends_with(".tailnet")
}

pub fn detect_tailscale_dns() -> Option<String> {
    let out = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let dns = v.pointer("/Self/DNSName")?.as_str()?;
    let host = dns.trim_end_matches('.').to_string();
    if host.is_empty() {
        None
    } else {
        info!("detected Tailscale DNS: {host}");
        Some(host)
    }
}

fn host_from_origin(origin: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(origin).context("invalid origin URL")?;
    let host = url
        .host_str()
        .context("origin missing host")?
        .trim_end_matches('.')
        .to_string();
    Ok(host)
}

fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    io::stdin().is_terminal()
}

fn read_line() -> anyhow::Result<String> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
