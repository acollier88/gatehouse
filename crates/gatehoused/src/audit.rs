use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use gatehouse_proto::Tier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "genesis";

/// One line of the append-only audit log. `hash` covers the JCS form of the
/// entry with `hash` removed, and `prev` chains to the previous line — so
/// truncation or edits anywhere break verification of every later line.
#[derive(Serialize, Deserialize, Debug)]
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

pub struct Audit {
    file: File,
    last_hash: String,
}

impl Audit {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let last_hash = match File::open(path) {
            Ok(f) => BufReader::new(f)
                .lines()
                .map_while(Result::ok)
                .last()
                .and_then(|line| serde_json::from_str::<Entry>(&line).ok())
                .map(|e| e.hash)
                .unwrap_or_else(|| GENESIS.to_string()),
            Err(_) => GENESIS.to_string(),
        };
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file, last_hash })
    }

    pub fn record(
        &mut self,
        digest: &str,
        summary: &str,
        tier: Tier,
        decision: &str,
        rule: &str,
    ) -> anyhow::Result<()> {
        let mut entry = Entry {
            ts: now_unix(),
            digest: digest.to_string(),
            summary: summary.to_string(),
            tier,
            decision: decision.to_string(),
            rule: rule.to_string(),
            prev: self.last_hash.clone(),
            hash: String::new(),
        };
        entry.hash = entry_hash(&entry)?;
        let line = serde_json::to_string(&entry)?;
        writeln!(self.file, "{line}")?;
        self.file.flush()?;
        self.last_hash = entry.hash;
        Ok(())
    }
}

/// Hash of the JCS form of the entry with `hash` blanked.
pub fn entry_hash(entry: &Entry) -> anyhow::Result<String> {
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

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_links_and_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("gh-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        {
            let mut a = Audit::open(&path).unwrap();
            a.record("d1", "Run `ls`", Tier::Allow, "allowed", "r1").unwrap();
            a.record("d2", "Run `git push`", Tier::AskStrong, "pending", "r2")
                .unwrap();
        }
        // Reopen and append; the chain must continue from the last hash.
        {
            let mut a = Audit::open(&path).unwrap();
            a.record("d2", "Run `git push`", Tier::AskStrong, "approved", "r2")
                .unwrap();
        }

        let lines: Vec<Entry> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].prev, GENESIS);
        assert_eq!(lines[1].prev, lines[0].hash);
        assert_eq!(lines[2].prev, lines[1].hash);
        for e in &lines {
            assert_eq!(e.hash, entry_hash(e).unwrap());
        }
        std::fs::remove_file(&path).ok();
    }
}
