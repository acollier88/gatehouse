//! Append-only audit log entry format and hash-chain verification.
//!
//! The daemon writes; `gate audit verify` (and anyone else) can check the chain
//! without talking to the daemon.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Tier;

pub const GENESIS: &str = "genesis";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub ts: i64,
    pub digest: String,
    pub summary: String,
    pub tier: Tier,
    pub decision: String,
    pub rule: String,
    pub prev: String,
    #[serde(default)]
    pub hash: String,
}

/// Hash of the JCS form of the entry with `hash` blanked.
pub fn entry_hash(entry: &Entry) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        ts: i64,
        digest: &'a str,
        summary: &'a str,
        tier: Tier,
        decision: &'a str,
        rule: &'a str,
        prev: &'a str,
    }
    let body = serde_jcs::to_string(&Body {
        ts: entry.ts,
        digest: &entry.digest,
        summary: &entry.summary,
        tier: entry.tier,
        decision: &entry.decision,
        rule: &entry.rule,
        prev: &entry.prev,
    })?;
    Ok(hex::encode(Sha256::digest(body.as_bytes())))
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json on line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("chain broken at line {line}: prev={got:?} expected={expected:?}")]
    Broken {
        line: usize,
        got: String,
        expected: String,
    },
    #[error("hash mismatch at line {line}")]
    HashMismatch { line: usize },
}

/// Verify an audit JSONL file. Returns the number of entries on success.
pub fn verify_file(path: &std::path::Path) -> Result<usize, VerifyError> {
    let text = std::fs::read_to_string(path)?;
    verify_text(&text)
}

pub fn verify_text(text: &str) -> Result<usize, VerifyError> {
    let mut prev = GENESIS.to_string();
    let mut count = 0usize;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_no = idx + 1;
        let entry: Entry = serde_json::from_str(line).map_err(|source| VerifyError::Json {
            line: line_no,
            source,
        })?;
        if entry.prev != prev {
            return Err(VerifyError::Broken {
                line: line_no,
                got: entry.prev,
                expected: prev,
            });
        }
        let expect = entry_hash(&entry).map_err(|source| VerifyError::Json {
            line: line_no,
            source,
        })?;
        if entry.hash != expect {
            return Err(VerifyError::HashMismatch { line: line_no });
        }
        prev = entry.hash;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_ok() {
        assert_eq!(verify_text("").unwrap(), 0);
    }
}
