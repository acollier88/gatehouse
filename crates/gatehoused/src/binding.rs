//! Request-bound WebAuthn challenges.
//!
//! The ceremony challenge is *derived* from the request rather than random, so
//! the assertion the authenticator signs covers the identity of the request it
//! releases:
//!
//! ```text
//! challenge = SHA-256( JCS({ "digest": <hex sha256 of canonical request>,
//!                            "nonce":  <per-pending-request nonce>,
//!                            "purpose":"gatehouse-approval-v1" }) )
//! ```
//!
//! JCS (RFC 8785) is the same canonicalization the request digest itself uses,
//! so the derivation is stable across processes and languages. `purpose`
//! domain-separates this hash from the request digest.
//!
//! webauthn-rs mints its own random challenge; [`bind_challenge`] replaces it
//! in both the client options and the server-side ceremony state. All
//! signature / origin / RP verification stays inside webauthn-rs.
//!
//! At release time [`assertion_challenge`] re-reads the challenge out of the
//! signed `clientDataJSON` and the caller compares it against a *fresh*
//! derivation from the pending request it is about to release — so the release
//! no longer trusts the in-memory ceremony↔digest pairing alone.

use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential, RequestChallengeResponse};

/// Domain separator: this hash is not the request digest and must never be
/// confused with it.
const PURPOSE: &str = "gatehouse-approval-v1";

#[derive(Serialize)]
struct ChallengeInput<'a> {
    digest: &'a str,
    nonce: &'a str,
    purpose: &'a str,
}

/// Deterministic ceremony challenge for one pending request.
pub fn derive_challenge(digest: &str, nonce: &str) -> [u8; 32] {
    let input = ChallengeInput {
        digest,
        nonce,
        purpose: PURPOSE,
    };
    // Serializing three owned string fields cannot fail.
    let canonical = serde_jcs::to_string(&input).expect("jcs of plain strings");
    Sha256::digest(canonical.as_bytes()).into()
}

/// Short code the human compares between the daemon terminal and the approval
/// page. Same value the daemon prints as `APPROVAL NEEDED [xxxxxxxx]`.
pub fn verification_code(digest: &str) -> String {
    digest.chars().take(8).collect()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Replace the random challenge webauthn-rs generated with `challenge`, in the
/// options sent to the client *and* in the ceremony state used to verify.
///
/// The state is patched through serde because webauthn-rs keeps the field
/// private; the shape is a base64url string in JSON for both `Base64UrlSafeData`
/// and `HumanBinaryData`, and a mismatch is caught by the round-trip failing.
pub fn bind_challenge(
    rcr: &mut RequestChallengeResponse,
    state: PasskeyAuthentication,
    challenge: &[u8; 32],
) -> Result<PasskeyAuthentication, String> {
    let encoded = serde_json::Value::String(b64(challenge));
    rcr.public_key.challenge = challenge.to_vec().into();

    let mut value =
        serde_json::to_value(&state).map_err(|e| format!("ceremony state not serializable: {e}"))?;
    let slot = value
        .get_mut("ast")
        .and_then(|ast| ast.get_mut("challenge"))
        .ok_or_else(|| "ceremony state has no challenge field".to_string())?;
    *slot = encoded;
    serde_json::from_value(value).map_err(|e| format!("ceremony state rejected rebind: {e}"))
}

/// The challenge the authenticator actually signed, read back out of
/// `clientDataJSON`. webauthn-rs has already verified the signature covers
/// these bytes by the time this is called.
pub fn assertion_challenge(cred: &PublicKeyCredential) -> Result<Vec<u8>, String> {
    let client_data: serde_json::Value =
        serde_json::from_slice(cred.response.client_data_json.as_ref())
            .map_err(|e| format!("clientDataJSON not JSON: {e}"))?;
    let encoded = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "clientDataJSON has no challenge".to_string())?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("clientDataJSON challenge not base64url: {e}"))
}

/// Fail closed unless the signed challenge is exactly the one derived from the
/// request being released.
pub fn check_bound(
    cred: &PublicKeyCredential,
    digest: &str,
    nonce: &str,
) -> Result<(), String> {
    let signed = assertion_challenge(cred)?;
    let expected = derive_challenge(digest, nonce);
    if signed.len() == expected.len() && bool::from(signed.ct_eq(&expected)) {
        Ok(())
    } else {
        Err("assertion is not bound to this request".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_request_same_challenge() {
        let a = derive_challenge("abc123", "nonce-1");
        let b = derive_challenge("abc123", "nonce-1");
        assert_eq!(a, b);
    }

    #[test]
    fn different_digest_or_nonce_changes_challenge() {
        let base = derive_challenge("abc123", "nonce-1");
        assert_ne!(base, derive_challenge("abc124", "nonce-1"));
        assert_ne!(base, derive_challenge("abc123", "nonce-2"));
    }

    /// Field boundaries must matter: concatenation-style derivations collide.
    #[test]
    fn field_split_is_not_ambiguous() {
        assert_ne!(derive_challenge("ab", "cd"), derive_challenge("abc", "d"));
    }

    #[test]
    fn verification_code_matches_terminal_prefix() {
        let digest = "0123456789abcdef0123456789abcdef";
        assert_eq!(verification_code(digest), &digest[..8]);
    }

    fn cred_with_challenge(encoded: &str) -> PublicKeyCredential {
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": encoded,
            "origin": "https://example.test",
        })
        .to_string();
        serde_json::from_value(serde_json::json!({
            "id": "aaaa",
            "rawId": b64(b"aaaa"),
            "type": "public-key",
            "extensions": {},
            "response": {
                "authenticatorData": b64(b"authdata"),
                "clientDataJSON": b64(client_data.as_bytes()),
                "signature": b64(b"sig"),
                "userHandle": null,
            },
        }))
        .expect("credential shape")
    }

    #[test]
    fn bound_assertion_is_accepted() {
        let challenge = derive_challenge("deadbeef", "n1");
        let cred = cred_with_challenge(&b64(&challenge));
        assert!(check_bound(&cred, "deadbeef", "n1").is_ok());
    }

    /// The relay-substitution case: a real gesture for request A must not
    /// release request B.
    #[test]
    fn assertion_for_another_request_fails_closed() {
        let challenge = derive_challenge("aaaaaaaa", "n1");
        let cred = cred_with_challenge(&b64(&challenge));
        assert!(check_bound(&cred, "bbbbbbbb", "n1").is_err());
        assert!(check_bound(&cred, "aaaaaaaa", "n2").is_err());
    }

    /// Guards the serde shape assumption in `bind_challenge`: if webauthn-rs
    /// ever changes how the ceremony state encodes its challenge, this fails
    /// rather than silently leaving a random challenge in place.
    #[test]
    fn bind_challenge_rewrites_options_and_state() {
        let state: PasskeyAuthentication = serde_json::from_value(serde_json::json!({
            "ast": {
                "credentials": [],
                "policy": "required",
                "challenge": b64(&[7u8; 32]),
                "appid": null,
                "allow_backup_eligible_upgrade": false,
            }
        }))
        .expect("ceremony state shape");
        let mut rcr: RequestChallengeResponse = serde_json::from_value(serde_json::json!({
            "publicKey": {
                "challenge": b64(&[7u8; 32]),
                "rpId": "localhost",
                "allowCredentials": [],
                "userVerification": "required",
            }
        }))
        .expect("challenge response shape");

        let challenge = derive_challenge("deadbeef", "n1");
        let bound = bind_challenge(&mut rcr, state, &challenge).expect("rebind");

        assert_eq!(rcr.public_key.challenge.as_ref(), challenge.as_slice());
        let encoded = serde_json::to_value(&bound).unwrap()["ast"]["challenge"].clone();
        assert_eq!(encoded, serde_json::Value::String(b64(&challenge)));
    }

    #[test]
    fn junk_client_data_fails_closed() {
        let cred = cred_with_challenge("!!!not-base64!!!");
        assert!(check_bound(&cred, "aaaaaaaa", "n1").is_err());
    }
}
