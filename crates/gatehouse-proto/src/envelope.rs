use serde::{Deserialize, Serialize};

/// How an approval was attested.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigScheme {
    /// Operator approved through the daemon's control channel with no
    /// cryptographic attestation. Phase 1 only; logged loudly.
    None,
    /// P-256 signature from a Secure Enclave key (Touch ID).
    P256,
    /// WebAuthn assertion from an enrolled passkey.
    Webauthn,
}

/// A decision bound to one specific request digest.
///
/// The signature (when present) covers [`ApprovalEnvelope::signing_payload`]:
/// digest, nonce, validity window, and key id — so an approval can neither be
/// replayed after expiry nor transplanted onto a different request.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ApprovalEnvelope {
    pub digest: String,
    /// Daemon-generated, single-use. The daemon remembers spent nonces for
    /// the validity window to block replays.
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
    pub scheme: SigScheme,
    /// Hex signature over `signing_payload()`. Empty for `SigScheme::None`.
    pub sig: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("envelope digest does not match request digest")]
    DigestMismatch,
    #[error("envelope expired")]
    Expired,
    #[error("envelope issued in the future")]
    NotYetValid,
}

impl ApprovalEnvelope {
    /// The exact bytes a signer must sign: JCS canonical JSON of everything
    /// except the signature itself.
    pub fn signing_payload(&self) -> Result<String, crate::ProtoError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            digest: &'a str,
            nonce: &'a str,
            issued_at: i64,
            expires_at: i64,
            key_id: &'a str,
            scheme: SigScheme,
        }
        Ok(serde_jcs::to_string(&Payload {
            digest: &self.digest,
            nonce: &self.nonce,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            key_id: &self.key_id,
            scheme: self.scheme,
        })?)
    }

    /// Structural checks: digest binding and validity window. Signature
    /// verification is the caller's job (it needs the key registry).
    pub fn check(&self, expected_digest: &str, now: i64) -> Result<(), EnvelopeError> {
        if self.digest != expected_digest {
            return Err(EnvelopeError::DigestMismatch);
        }
        if now > self.expires_at {
            return Err(EnvelopeError::Expired);
        }
        if self.issued_at > now {
            return Err(EnvelopeError::NotYetValid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(digest: &str) -> ApprovalEnvelope {
        ApprovalEnvelope {
            digest: digest.into(),
            nonce: "n1".into(),
            issued_at: 100,
            expires_at: 220,
            key_id: "operator".into(),
            scheme: SigScheme::None,
            sig: String::new(),
        }
    }

    #[test]
    fn rejects_wrong_digest_even_if_unexpired() {
        assert_eq!(
            env("aaaa").check("bbbb", 150),
            Err(EnvelopeError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_expired_and_future_envelopes() {
        assert_eq!(env("d").check("d", 300), Err(EnvelopeError::Expired));
        assert_eq!(env("d").check("d", 50), Err(EnvelopeError::NotYetValid));
        assert_eq!(env("d").check("d", 150), Ok(()));
    }
}
