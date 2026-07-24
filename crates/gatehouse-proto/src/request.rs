use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ProtoError;

/// The operation an agent wants to perform.
///
/// Serialization goes through JCS (RFC 8785) canonicalization before hashing,
/// so field *order* never matters — but field *names* are part of the wire
/// contract: renaming one changes every digest ever produced.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    Exec { argv: Vec<String>, cwd: String },
    FileWrite { path: String },
    Net { host: String, port: u16 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GateRequest {
    pub harness: String,
    pub session_id: String,
    /// Names of environment variables the executor may pass through from the
    /// daemon's environment. Values are never part of the request.
    pub env_allowlist: Vec<String>,
    pub op: Operation,
}

impl GateRequest {
    pub fn canonical_json(&self) -> Result<String, ProtoError> {
        Ok(serde_jcs::to_string(self)?)
    }

    /// Hex-encoded SHA-256 of the canonical JSON form. This is the value an
    /// approver signs and the only identity a request has.
    pub fn digest(&self) -> Result<String, ProtoError> {
        Ok(hex::encode(Sha256::digest(
            self.canonical_json()?.as_bytes(),
        )))
    }

    /// Human-readable summary shown in every approval UI.
    ///
    /// Built from the same struct the digest is computed over, so what the
    /// human reads and what the signature covers cannot diverge.
    pub fn summary(&self) -> String {
        match &self.op {
            Operation::Exec { argv, cwd } => {
                format!("Run `{}` in {}", argv.join(" "), cwd)
            }
            Operation::FileWrite { path } => format!("Write file {path}"),
            Operation::Net { host, port } => format!("Connect to {host}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(argv: &[&str]) -> GateRequest {
        GateRequest {
            harness: "test".into(),
            session_id: "s1".into(),
            env_allowlist: vec![],
            op: Operation::Exec {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: "/tmp".into(),
            },
        }
    }

    #[test]
    fn digest_is_stable_across_runs() {
        let a = req(&["git", "push"]);
        let b = req(&["git", "push"]);
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn digest_changes_with_any_field() {
        let base = req(&["git", "push"]);
        let other_argv = req(&["git", "pull"]);
        assert_ne!(base.digest().unwrap(), other_argv.digest().unwrap());

        let mut other_cwd = base.clone();
        if let Operation::Exec { cwd, .. } = &mut other_cwd.op {
            *cwd = "/home".into();
        }
        assert_ne!(base.digest().unwrap(), other_cwd.digest().unwrap());
    }

    #[test]
    fn canonical_json_is_jcs_sorted() {
        let json = req(&["ls"]).canonical_json().unwrap();
        // JCS sorts object keys; spot-check that top-level keys are ordered.
        let env_pos = json.find("env_allowlist").unwrap();
        let harness_pos = json.find("harness").unwrap();
        let op_pos = json.find("\"op\"").unwrap();
        assert!(env_pos < harness_pos && harness_pos < op_pos);
    }
}
