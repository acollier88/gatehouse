//! Bootstrap and load mTLS material for the phone approval relay.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use gatehouse_proto::{paths, RelayConfig};
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, KeyPair, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls::server::WebPkiClientVerifier;
use tracing::info;

const CA_CERT: &str = "ca.pem";
const RELAY_CERT: &str = "relay-cert.pem";
const RELAY_KEY: &str = "relay-key.pem";
const DAEMON_CERT: &str = "daemon-cert.pem";
const DAEMON_KEY: &str = "daemon-key.pem";

pub struct RelayMaterial {
    pub config: RelayConfig,
    pub dir: PathBuf,
}

impl RelayMaterial {
    pub fn load() -> anyhow::Result<Self> {
        let dir = paths::relay_dir();
        let cfg_path = paths::relay_config_path();
        let text = std::fs::read_to_string(&cfg_path)
            .with_context(|| format!("missing {}; run: gatehoused relay-init", cfg_path.display()))?;
        let config: RelayConfig = serde_json::from_str(&text)?;
        Ok(Self { config, dir })
    }

    pub fn init(
        rp_id: &str,
        origin: &str,
        listen: &str,
        daemon_listen: &str,
        force: bool,
        keep_token: Option<String>,
        transport: Option<String>,
    ) -> anyhow::Result<Self> {
        let dir = paths::relay_dir();
        std::fs::create_dir_all(&dir)?;
        let cfg_path = paths::relay_config_path();
        if cfg_path.exists() && !force {
            bail!(
                "{} already exists (pass --force to overwrite)",
                cfg_path.display()
            );
        }

        let mut ca_params = CertificateParams::new(vec!["Gatehouse Relay CA".into()])?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_cert = ca_params.self_signed(&ca_key)?;

        let relay_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut relay_params = CertificateParams::new(vec![rp_id.to_string()])?;
        relay_params
            .subject_alt_names
            .push(SanType::DnsName(rp_id.try_into()?));
        if let Ok(ip) = "127.0.0.1".parse() {
            relay_params.subject_alt_names.push(SanType::IpAddress(ip));
        }
        relay_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        relay_params.extended_key_usages =
            vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let relay_cert = relay_params.signed_by(&relay_key, &ca_cert, &ca_key)?;

        let daemon_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut daemon_params = CertificateParams::new(vec!["gatehouse-daemon".into()])?;
        daemon_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        daemon_params.extended_key_usages =
            vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let daemon_cert = daemon_params.signed_by(&daemon_key, &ca_cert, &ca_key)?;

        write_pem(dir.join(CA_CERT), ca_cert.pem())?;
        write_pem(dir.join(RELAY_CERT), relay_cert.pem())?;
        write_pem(dir.join(RELAY_KEY), relay_key.serialize_pem())?;
        write_pem(dir.join(DAEMON_CERT), daemon_cert.pem())?;
        write_pem(dir.join(DAEMON_KEY), daemon_key.serialize_pem())?;

        let phone_token = keep_token.unwrap_or_else(new_token);
        let config = RelayConfig {
            rp_id: rp_id.to_string(),
            origin: origin.trim_end_matches('/').to_string(),
            phone_token: phone_token.clone(),
            listen: listen.to_string(),
            daemon_listen: daemon_listen.to_string(),
            transport,
        };
        let cfg_json = serde_json::to_string_pretty(&config)?;
        write_pem(&cfg_path, cfg_json)?;

        info!("relay material written to {}", dir.display());
        info!("phone URL: {}/?t={}", config.origin, phone_token);
        info!("daemon mTLS listen hint: {}", daemon_listen);
        Ok(Self { config, dir })
    }

    pub fn phone_url(&self) -> String {
        format!("{}/?t={}", self.config.origin, self.config.phone_token)
    }

    pub fn relay_server_config(&self) -> anyhow::Result<ServerConfig> {
        let certs = load_certs(&self.dir.join(RELAY_CERT))?;
        let key = load_key(&self.dir.join(RELAY_KEY))?;
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("relay server TLS config")
    }

    /// Daemon-facing listener: requires a client cert signed by our CA.
    pub fn daemon_server_config(&self) -> anyhow::Result<ServerConfig> {
        let mut roots = RootCertStore::empty();
        for c in load_certs(&self.dir.join(CA_CERT))? {
            roots.add(c).context("add CA to root store")?;
        }
        let verifier = WebPkiClientVerifier::builder(std::sync::Arc::new(roots))
            .build()
            .context("client verifier")?;
        let certs = load_certs(&self.dir.join(RELAY_CERT))?;
        let key = load_key(&self.dir.join(RELAY_KEY))?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("daemon mTLS server config")
    }

    pub fn daemon_client_config(&self) -> anyhow::Result<ClientConfig> {
        let mut roots = RootCertStore::empty();
        for c in load_certs(&self.dir.join(CA_CERT))? {
            roots.add(c)?;
        }
        // Also trust webpki roots so wss:// through public CAs still works if
        // someone terminates TLS elsewhere; our CA covers self-hosted relay.
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let certs = load_certs(&self.dir.join(DAEMON_CERT))?;
        let key = load_key(&self.dir.join(DAEMON_KEY))?;
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .context("daemon mTLS client config")
    }
}

fn new_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn write_pem(path: impl AsRef<Path>, pem: impl AsRef<[u8]>) -> anyhow::Result<()> {
    std::fs::write(path.as_ref(), pem.as_ref())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path)?;
    let mut reader = std::io::Cursor::new(data);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse certs {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates in {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path)?;
    let mut reader = std::io::Cursor::new(data);
    let key = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse key {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", path.display()))?;
    // Ensure we own a PKCS8-shaped key for rustls.
    Ok(match key {
        PrivateKeyDer::Pkcs8(k) => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec())),
        other => other,
    })
}
