//! Email-ownership verification codes for the public self-service apply flow.
//!
//! Ported from the advanced gateway's `advanced/api/email_verify.rs` so both
//! editions share the same mechanism: the applicant's contact email is
//! entered ONCE, a 6-digit code is mailed, the frontend may async-check
//! (unlocks submit; never grants credentials), and the full submit
//! re-verifies server-side.
//!
//! Identity is a TRIPLE match — `name` + `email` + `code` (unified activation
//! reform §3.3): `issue` records the name with the code, and `verify` rejects
//! the pair unless all three agree. Knowing only the address and the mailed
//! code is therefore not enough to apply. The name comparison is exact
//! (case-sensitive), matching the applicant-name binding rule.
//!
//! Storage: in-process memory map (same trust level as the GCRA limiters —
//! single-instance deployment premise). Semantics:
//! - code TTL 10 min, cooldown 120 s between sends (resend overwrites the
//!   code AND resets the attempt budget)
//! - max 5 verification attempts per code lifetime (frontend check and
//!   submit share the budget); 5th failure locks until the code expires
//!   (resend clears)
//! - a name that does not match the issued entry burns an attempt exactly
//!   like a wrong code
//! - no per-email daily send cap (ruled: targeted mitigation only if
//!   abuse shows up in operations)
//!
//! Deliberately NOT a database table: verification state is transient
//! (TTL-bounded) and single-instance, so a product schema table would be a
//! test/pilot convenience leaking into the product DB.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) const CODE_TTL: Duration = Duration::from_secs(600); // 10 min
pub(crate) const SEND_COOLDOWN: Duration = Duration::from_secs(120); // 120 s
pub(crate) const MAX_ATTEMPTS: u32 = 5;

#[derive(Clone)]
struct VerifyEntry {
    /// Applicant name recorded at send time; part of the verified identity.
    name: String,
    code: String,
    expires_at: Instant,
    tries: u32,
    sent_at: Instant,
}

static ENTRIES: std::sync::LazyLock<Mutex<HashMap<String, VerifyEntry>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn gen_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1_000_000))
}

fn prune_expired(map: &mut HashMap<String, VerifyEntry>) {
    let now = Instant::now();
    map.retain(|_, e| e.expires_at > now);
}

/// Why a submitted identity was rejected. The two cases need different words
/// in the UI: a missing code (expired, never sent, or locked out) is fixed by
/// requesting a new one, while a wrong code/name is fixed by re-reading the
/// email or correcting the name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerifyError {
    /// No live code for this address — expired, never issued, or the attempt
    /// budget is used up (a resend issues a new code with a fresh budget).
    NoCode,
    /// The code did not match; this many attempts remain.
    Attempts(u32),
}

/// Check a submitted name+email+code against the current entry. Shared by the
/// frontend async-check and the full-submit server-side verification — one
/// attempt budget per code lifetime. Ok(()) consumes nothing on success (the
/// code stays valid until TTL — a submit then proceeds with its own business
/// checks). A name mismatch burns an attempt exactly like a code mismatch.
pub(crate) fn verify(email: &str, name: &str, code: &str) -> Result<(), VerifyError> {
    let mut map = ENTRIES.lock().unwrap_or_else(|e| e.into_inner());
    prune_expired(&mut map);
    let Some(entry) = map.get(email) else {
        return Err(VerifyError::NoCode);
    };
    if entry.name == name && entry.code == code && entry.expires_at > Instant::now() {
        Ok(())
    } else {
        let e = map.get_mut(email).unwrap();
        e.tries += 1;
        if e.tries >= MAX_ATTEMPTS {
            // Locked: drop the entry — the applicant must request a new code,
            // and until then every attempt reports NoCode.
            map.remove(email);
            return Err(VerifyError::NoCode);
        }
        Err(VerifyError::Attempts(MAX_ATTEMPTS - e.tries))
    }
}

/// Record a code (bound to name+email), enforcing the resend cooldown.
/// Ok → code recorded; Err(secs) → cooldown not elapsed.
pub(crate) fn issue(email: &str, name: &str) -> Result<String, u64> {
    let mut map = ENTRIES.lock().unwrap_or_else(|e| e.into_inner());
    prune_expired(&mut map);
    if let Some(e) = map.get(email) {
        let elapsed = e.sent_at.elapsed();
        if elapsed < SEND_COOLDOWN {
            return Err((SEND_COOLDOWN - elapsed).as_secs() + 1);
        }
    }
    let code = gen_code();
    map.insert(
        email.to_string(),
        VerifyEntry {
            name: name.to_string(),
            code: code.clone(),
            expires_at: Instant::now() + CODE_TTL,
            tries: 0,
            sent_at: Instant::now(),
        },
    );
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_roundtrip() {
        let email = "t1@example.com";
        let name = "Meter";
        let code = issue(email, name).expect("first issue ok");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(verify(email, name, &code).is_ok());
    }

    #[test]
    fn name_mismatch_rejects_correct_code() {
        let email = "t1b@example.com";
        let code = issue(email, "Meter").unwrap();
        // Right address + right code, wrong name (and wrong case) must fail.
        assert_eq!(
            verify(email, "meter", &code),
            Err(VerifyError::Attempts(4)),
            "name is part of the verified identity"
        );
        assert_eq!(
            verify(email, "Someone", &code),
            Err(VerifyError::Attempts(3))
        );
        // The correct triple still passes while attempts remain.
        assert!(verify(email, "Meter", &code).is_ok());
    }

    #[test]
    fn wrong_code_counts_attempts_then_locks() {
        let email = "t2@example.com";
        let name = "Meter";
        let code = issue(email, name).unwrap();
        // 4 wrong attempts leave 1 remaining.
        for remaining in (1..=4).rev() {
            match verify(email, name, "000000") {
                Err(VerifyError::Attempts(r)) => assert_eq!(r, remaining),
                other => panic!("wrong code must report attempts left, got {other:?}"),
            }
        }
        // 5th wrong attempt locks the code away entirely.
        assert_eq!(verify(email, name, "000000"), Err(VerifyError::NoCode));
        // Even the right code is gone now.
        assert!(verify(email, name, &code).is_err());
    }

    #[test]
    fn unknown_email_reports_no_code() {
        assert_eq!(
            verify("nobody@example.com", "Meter", "123456"),
            Err(VerifyError::NoCode)
        );
    }

    #[test]
    fn issue_is_digit_code_and_overwrites() {
        let email = "t4@example.com";
        let name = "Meter";
        let c1 = issue(email, name).unwrap();
        // Simulate cooldown expiry by rewriting sent_at via direct map
        // manipulation (tests only).
        {
            let mut map = ENTRIES.lock().unwrap_or_else(|e| e.into_inner());
            let e = map.get_mut(email).unwrap();
            e.sent_at = Instant::now() - SEND_COOLDOWN - Duration::from_secs(1);
        }
        let c2 = issue(email, name).unwrap();
        assert_ne!(c1, c2, "resend must overwrite with a fresh code");
        assert!(verify(email, name, &c2).is_ok());
        // A resend replaces the code, but the entry is live: the old code
        // reads as a plain mismatch (attempts left), not as a missing code.
        assert_eq!(
            verify(email, name, &c1),
            Err(VerifyError::Attempts(4)),
            "old code must be rejected"
        );
    }

    #[test]
    fn cooldown_enforced() {
        let email = "t5@example.com";
        issue(email, "Meter").unwrap();
        match issue(email, "Meter") {
            Err(secs) => assert!(secs > 0 && secs <= 121),
            Ok(_) => panic!("cooldown must block immediate resend"),
        }
    }

    #[test]
    fn resend_rebinds_name() {
        let email = "t6@example.com";
        issue(email, "Meter").unwrap();
        {
            let mut map = ENTRIES.lock().unwrap_or_else(|e| e.into_inner());
            let e = map.get_mut(email).unwrap();
            e.sent_at = Instant::now() - SEND_COOLDOWN - Duration::from_secs(1);
        }
        let code = issue(email, "Other").unwrap();
        // The latest send defines the identity: the old name no longer works.
        assert_eq!(verify(email, "Meter", &code), Err(VerifyError::Attempts(4)));
        assert!(verify(email, "Other", &code).is_ok());
    }
}
