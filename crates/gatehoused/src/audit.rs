use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use gatehouse_proto::audit_log::{entry_hash, Entry, GENESIS};
use gatehouse_proto::Tier;

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
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
        let last_hash = match std::fs::read_to_string(path) {
            Ok(text) => text
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .and_then(|line| serde_json::from_str::<Entry>(line).ok())
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

#[cfg(test)]
mod tests {
    use super::*;
    use gatehouse_proto::audit_log::verify_file;

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
        {
            let mut a = Audit::open(&path).unwrap();
            a.record("d2", "Run `git push`", Tier::AskStrong, "approved", "r2")
                .unwrap();
        }

        assert_eq!(verify_file(&path).unwrap(), 3);
        std::fs::remove_file(&path).ok();
    }
}
