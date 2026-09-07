use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use gatehouse_proto::{ApprovalEnvelope, GateRequest, Tier};
use tokio::sync::oneshot;

/// A submit waiting on a human. The submit task holds the receiver; whoever
/// decides sends `Some(envelope)` to approve or `None` to deny.
pub struct Pending {
    pub request: GateRequest,
    pub tier: Tier,
    pub nonce: String,
    pub submitted: Instant,
    pub tx: oneshot::Sender<Option<ApprovalEnvelope>>,
}

pub struct Grant {
    pub argv_glob: String,
    pub expires: Instant,
}

#[derive(Default)]
pub struct Shared {
    pub pending: Mutex<HashMap<String, Pending>>,
    pub grants: Mutex<Vec<Grant>>,
}

impl Shared {
    /// True if a live session grant covers the joined argv.
    pub fn grant_matches(&self, argv_joined: &str) -> bool {
        let mut grants = self.grants.lock().unwrap();
        let now = Instant::now();
        grants.retain(|g| g.expires > now);
        grants.iter().any(|g| {
            glob::Pattern::new(&g.argv_glob)
                .map(|p| p.matches(argv_joined))
                .unwrap_or(false)
        })
    }

    pub fn add_grant(&self, argv_glob: String, ttl: Duration) {
        self.grants.lock().unwrap().push(Grant {
            argv_glob,
            expires: Instant::now() + ttl,
        });
    }

    pub fn grant_snapshot(&self) -> Vec<gatehouse_proto::GrantInfo> {
        let mut grants = self.grants.lock().unwrap();
        let now = Instant::now();
        grants.retain(|g| g.expires > now);
        grants
            .iter()
            .map(|g| gatehouse_proto::GrantInfo {
                argv_glob: g.argv_glob.clone(),
                expires_in_secs: (g.expires - now).as_secs(),
            })
            .collect()
    }

    /// Nonce of a pending request, without consuming it. Approval paths need
    /// it to re-derive the ceremony challenge before releasing.
    pub fn pending_nonce(&self, digest: &str) -> Option<String> {
        self.pending
            .lock()
            .unwrap()
            .get(digest)
            .map(|p| p.nonce.clone())
    }

    /// Remove and return the pending entry uniquely identified by a digest
    /// prefix. Errors on no match or ambiguity.
    pub fn take_pending(&self, digest_prefix: &str) -> Result<(String, Pending), String> {
        let mut pending = self.pending.lock().unwrap();
        let matches: Vec<String> = pending
            .keys()
            .filter(|d| d.starts_with(digest_prefix))
            .cloned()
            .collect();
        match matches.as_slice() {
            [] => Err(format!("no pending request matches '{digest_prefix}'")),
            [digest] => {
                let digest = digest.clone();
                let entry = pending.remove(&digest).unwrap();
                Ok((digest, entry))
            }
            _ => Err(format!(
                "'{digest_prefix}' is ambiguous ({} matches); use more characters",
                matches.len()
            )),
        }
    }

    pub fn pending_snapshot(&self) -> Vec<gatehouse_proto::PendingEntry> {
        let pending = self.pending.lock().unwrap();
        let mut entries: Vec<_> = pending
            .iter()
            .map(|(digest, p)| gatehouse_proto::PendingEntry {
                digest: digest.clone(),
                summary: p.request.summary(),
                tier: p.tier,
                harness: p.request.harness.clone(),
                age_secs: p.submitted.elapsed().as_secs(),
            })
            .collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.age_secs));
        entries
    }
}
