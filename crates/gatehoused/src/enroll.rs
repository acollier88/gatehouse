//! One-time enrollment codes.
//!
//! The bearer token on the approval page only proves someone has the URL.
//! Enrolling a passkey mints a *new approver*, so it additionally requires a
//! code the operator reads off their own terminal (`gate enroll-code`).
//! Codes are single-use and short-lived; comparison is constant-time.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use subtle::ConstantTimeEq;

/// Long enough that guessing inside the TTY window is hopeless, short enough
/// to type on a phone.
const CODE_LEN: usize = 8;
pub const CODE_TTL: Duration = Duration::from_secs(300);

/// Unambiguous on a phone keyboard: no 0/O, 1/I/L.
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

struct Code {
    value: String,
    expires: Instant,
}

#[derive(Default)]
pub struct EnrollCodes {
    codes: Mutex<Vec<Code>>,
}

impl EnrollCodes {
    /// Mint a code valid for [`CODE_TTL`]. Previous unused codes stay valid
    /// until they expire — re-running the command must not lock out an
    /// operator who is mid-typing.
    pub fn issue(&self) -> String {
        // Rejection sampling: a plain `% len` would bias the first few letters.
        let limit = (256 / ALPHABET.len()) * ALPHABET.len();
        let mut value = String::with_capacity(CODE_LEN);
        let mut buf = [0u8; CODE_LEN * 2];
        while value.len() < CODE_LEN {
            rand::thread_rng().fill_bytes(&mut buf);
            for b in buf.iter() {
                if (*b as usize) < limit && value.len() < CODE_LEN {
                    value.push(ALPHABET[*b as usize % ALPHABET.len()] as char);
                }
            }
        }
        let mut codes = self.codes.lock().unwrap();
        codes.retain(|c| c.expires > Instant::now());
        codes.push(Code {
            value: value.clone(),
            expires: Instant::now() + CODE_TTL,
        });
        value
    }

    /// Consume `presented` if it matches a live code. Single-use: a successful
    /// redemption removes it.
    pub fn redeem(&self, presented: &str) -> bool {
        let presented = presented.trim().to_ascii_uppercase();
        let mut codes = self.codes.lock().unwrap();
        let now = Instant::now();
        codes.retain(|c| c.expires > now);
        // Scan every live code so the work does not depend on which one hits.
        let mut hit: Option<usize> = None;
        for (i, c) in codes.iter().enumerate() {
            let same = c.value.len() == presented.len()
                && bool::from(c.value.as_bytes().ct_eq(presented.as_bytes()));
            if same {
                hit = Some(i);
            }
        }
        match hit {
            Some(i) => {
                codes.remove(i);
                true
            }
            None => false,
        }
    }

    pub fn live(&self) -> usize {
        let mut codes = self.codes.lock().unwrap();
        let now = Instant::now();
        codes.retain(|c| c.expires > now);
        codes.len()
    }

    #[cfg(test)]
    fn issue_with_ttl(&self, ttl: Duration) -> String {
        let value = self.issue();
        let mut codes = self.codes.lock().unwrap();
        for c in codes.iter_mut() {
            if c.value == value {
                c.expires = Instant::now() + ttl;
            }
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_single_use() {
        let codes = EnrollCodes::default();
        let code = codes.issue();
        assert!(codes.redeem(&code));
        assert!(!codes.redeem(&code), "a redeemed code must not work twice");
    }

    #[test]
    fn wrong_code_is_rejected() {
        let codes = EnrollCodes::default();
        let code = codes.issue();
        assert!(!codes.redeem("AAAAAAAA"));
        assert!(!codes.redeem(""));
        assert!(!codes.redeem(&format!("{code}X")));
        assert!(codes.redeem(&code), "a bad guess must not consume the code");
    }

    #[test]
    fn code_expires() {
        let codes = EnrollCodes::default();
        let code = codes.issue_with_ttl(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!codes.redeem(&code));
        assert_eq!(codes.live(), 0);
    }

    #[test]
    fn codes_are_shaped_and_distinct() {
        let codes = EnrollCodes::default();
        let a = codes.issue();
        let b = codes.issue();
        assert_eq!(a.len(), CODE_LEN);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| ALPHABET.contains(&c)));
    }

    #[test]
    fn entry_is_case_insensitive() {
        let codes = EnrollCodes::default();
        let code = codes.issue();
        assert!(codes.redeem(&format!("  {}  ", code.to_ascii_lowercase())));
    }
}
