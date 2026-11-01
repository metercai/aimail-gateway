//! Email body preprocessing: whitelist instruction filtering — used by
//! the bodyproc pipeline before webhook delivery.
//!
//! strip_quoted_text / parse_recipients / preprocess_body were removed:
//! bodyproc.rs handles quote-stripping and layer decomposition internally.

use regex::Regex;
use std::sync::LazyLock;

// ═══════════════════════════════════════════════════════════════
// Whitelist instruction stripping (security boundary)
// ═══════════════════════════════════════════════════════════════

static RE_WL_ADD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(add|allow|whitelist)\s+[\w.@+-]+\s+(to|into|in)\s+(my\s+)?(whitelist|contacts)",
    )
    .unwrap()
});

static RE_WL_REMOVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(remove|block|delete|blacklist)\s+[\w.@+-]+\s+(from\s+)?(my\s+)?(whitelist|contacts)",
    )
    .unwrap()
});

static RE_WL_LET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)let\s+[\w.@+-]+\s+(in|through|contact\s+me)").unwrap());

/// Strip whitelist management commands from email body.
/// Whitelist changes must go through admin panel or CLI — email is not trusted.
/// Returns `(cleaned_body, was_stripped)`.
pub fn strip_whitelist_instructions(body: &str) -> (String, bool) {
    if body.is_empty() {
        return (String::new(), false);
    }

    let lines: Vec<&str> = body.lines().collect();
    let mut filtered = Vec::with_capacity(lines.len());
    let mut stripped = false;

    for line in &lines {
        if RE_WL_ADD.is_match(line) || RE_WL_REMOVE.is_match(line) || RE_WL_LET.is_match(line) {
            stripped = true;
            continue;
        }
        filtered.push(*line);
    }

    if stripped {
        (filtered.join("\n").trim().to_string(), true)
    } else {
        (body.to_string(), false)
    }
}

#[cfg(test)]
mod tests {
    use crate::core::email::preprocess::strip_whitelist_instructions;

    #[test]
    fn test_strip_wl_add() {
        let body = "Hi,\n\nPlease add bob@example.com to my whitelist.\n\nThanks!";
        let (cleaned, stripped) = strip_whitelist_instructions(body);
        assert!(stripped);
        assert!(!cleaned.contains("add bob@example.com"));
        assert!(cleaned.contains("Hi"));
        assert!(cleaned.contains("Thanks"));
    }

    #[test]
    fn test_strip_wl_remove() {
        let body = "remove spam@bad.com from whitelist\n\nAlso, here is the report.";
        let (cleaned, stripped) = strip_whitelist_instructions(body);
        assert!(stripped);
        assert!(!cleaned.contains("spam@bad.com"));
        assert!(cleaned.contains("report"));
    }

    #[test]
    fn test_strip_wl_allow_variant() {
        let body = "allow contact@vendor.com to my contacts\n\nMeeting at 3pm.";
        let (cleaned, stripped) = strip_whitelist_instructions(body);
        assert!(stripped);
        assert!(!cleaned.contains("contact@vendor.com"));
        assert!(cleaned.contains("Meeting"));
    }

    #[test]
    fn test_strip_wl_let_variant() {
        let body = "let friend@work.com in\n\nSee you tomorrow.";
        let (cleaned, stripped) = strip_whitelist_instructions(body);
        assert!(stripped);
        assert!(!cleaned.contains("friend@work.com"));
        assert!(cleaned.contains("See you tomorrow"));
    }

    #[test]
    fn test_no_wl_instructions() {
        let body = "Here is a normal email about project updates.";
        let (cleaned, stripped) = strip_whitelist_instructions(body);
        assert!(!stripped);
        assert_eq!(cleaned, body);
    }
}
