//! Email body preprocessing: quote stripping, whitelist instruction filtering,
//! and recipient parsing — all in Rust before webhook delivery.

use regex::Regex;
use std::sync::LazyLock;

// ═══════════════════════════════════════════════════════════════
// Quoted text stripping
// ═══════════════════════════════════════════════════════════════

static RE_ON_WROTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^On\s+.+\s+wrote:\s*$").unwrap());

static RE_ORIG_MSG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^-{3,}\s*Original\s+Message\s*-{3,}\s*$").unwrap());

/// Strip quoted historical content from an email body.
/// Handles: "On ... wrote:", "---Original Message---", and ">" lines.
/// Returns `(cleaned_body, was_stripped)`.
pub fn strip_quoted_text(body: &str) -> (String, bool) {
    if body.is_empty() {
        return (String::new(), false);
    }

    // Pattern 1: "On ... wrote:" separator
    if let Some(m) = RE_ON_WROTE.find(body) {
        let cleaned = body[..m.start()].trim().to_string();
        if !cleaned.is_empty() {
            return (cleaned, true);
        }
    }

    // Pattern 2: "---Original Message---" separator
    if let Some(m) = RE_ORIG_MSG.find(body) {
        let cleaned = body[..m.start()].trim().to_string();
        if !cleaned.is_empty() {
            return (cleaned, true);
        }
    }

    // Pattern 3: Lines starting with ">" — take content before first > line
    let mut new_content = Vec::new();
    let mut found_quote = false;
    for line in body.lines() {
        if line.trim_start().starts_with('>') {
            found_quote = true;
            break;
        }
        new_content.push(line);
    }
    if found_quote && !new_content.is_empty() {
        let cleaned = new_content.join("\n").trim().to_string();
        if !cleaned.is_empty() {
            return (cleaned, true);
        }
    }

    (body.to_string(), false)
}

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

// ═══════════════════════════════════════════════════════════════
// Recipient parsing
// ═══════════════════════════════════════════════════════════════

/// Parse `to` and `cc` fields into a deduplicated list of recipients.
/// Handles comma-separated addresses with optional whitespace; case-insensitive dedup.
pub fn parse_recipients(to: &str, cc: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    for field in [to, cc] {
        if field.is_empty() {
            continue;
        }
        for addr in field.split(',') {
            let addr = addr.trim().to_lowercase();
            if !addr.is_empty() && seen.insert(addr.clone()) {
                result.push(addr);
            }
        }
    }

    result
}

// ═══════════════════════════════════════════════════════════════
// Full preprocessing pipeline
// ═══════════════════════════════════════════════════════════════

/// Result of the full preprocessing pipeline.
#[derive(Debug, Default)]
pub struct PreprocessResult {
    /// Cleaned body (whitelist instructions and quoted text removed).
    pub body: String,
}

/// Run the full preprocessing pipeline on an email body.
pub fn preprocess_body(body: &str) -> PreprocessResult {
    let mut current_body = body.to_string();

    // Step 1: Strip whitelist instructions (security boundary — must be first)
    let (clean, _wl) = strip_whitelist_instructions(&current_body);
    current_body = clean;

    // Step 2: Strip quoted text
    let (clean, _quoted) = strip_quoted_text(&current_body);
    current_body = clean;

    PreprocessResult { body: current_body }
}

#[cfg(test)]
mod tests {
    use crate::core::email::preprocess::{
        parse_recipients, preprocess_body, strip_quoted_text, strip_whitelist_instructions,
    };

    // ═══════════════════════════════════════════════════════════════
    // Quoted text stripping tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_strip_on_wrote_standard() {
        let body = "Please review the document.\n\nOn Mon, Jan 1, 2024 at 3:00 PM John <john@example.com> wrote:\n> Old message here";
        let (cleaned, stripped) = strip_quoted_text(body);
        assert!(stripped);
        assert!(cleaned.contains("Please review"));
        assert!(!cleaned.contains("Old message"));
    }

    #[test]
    fn test_strip_outlook_original_message() {
        let body = "Here is the updated file.\n\n-----Original Message-----\nFrom: Alice\nSent: Monday\nSubject: Old\n\nOld content";
        let (cleaned, stripped) = strip_quoted_text(body);
        assert!(stripped);
        assert!(cleaned.contains("updated file"));
        assert!(!cleaned.contains("Old content"));
    }

    #[test]
    fn test_strip_gt_quoting() {
        let body = "My new reply.\n\n> Previous message line 1\n> Previous message line 2";
        let (cleaned, stripped) = strip_quoted_text(body);
        assert!(stripped);
        assert!(cleaned.contains("My new reply"));
        assert!(!cleaned.contains("Previous message"));
    }

    #[test]
    fn test_no_quotes_clean_body() {
        let body = "Just a simple message with nothing to strip.";
        let (cleaned, stripped) = strip_quoted_text(body);
        assert!(!stripped);
        assert_eq!(cleaned, body);
    }

    #[test]
    fn test_strip_empty_body() {
        let (cleaned, stripped) = strip_quoted_text("");
        assert!(!stripped);
        assert!(cleaned.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════
    // Whitelist instruction stripping tests
    // ═══════════════════════════════════════════════════════════════

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

    // ═══════════════════════════════════════════════════════════════
    // Full pipeline tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_preprocess_mixed_quotes_and_wl() {
        let body = "add user@test.com to whitelist\n\nPlease check this.\n\nOn Tue, at 5pm, someone wrote:\n> Old stuff";
        let result = preprocess_body(body);
        assert!(!result.body.contains("add user@test.com"));
        assert!(!result.body.contains("wrote:"));
        assert!(result.body.contains("Please check this"));
        let cleaned = &result.body;
        assert!(!cleaned.contains("whitelist"));
        assert!(!cleaned.contains("Old stuff"));
        assert!(cleaned.contains("Please check this"));
    }

    #[test]
    fn test_preprocess_clean_body_unchanged() {
        let body = "Hello, just checking in. No quotes, no whitelist commands.";
        let result = preprocess_body(body);
        assert_eq!(result.body, body);
    }

    // Recipient parsing tests (parse_recipients, not preprocess_body)
    #[test]
    fn test_parse_recipients_dedup() {
        let result = parse_recipients("a@x.com, b@x.com", "b@x.com, a@x.com");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_recipients_empty() {
        let result = parse_recipients("", "");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_recipients_case_insensitive_dedup() {
        let result = parse_recipients("User@Example.com", "user@example.com");
        assert_eq!(result.len(), 1);
    }

    // Recipient parsing tests

    #[test]
    fn test_parse_recipients_basic() {
        let result = parse_recipients("a@b.com, c@d.com", "e@f.com");
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"a@b.com".to_string()));
        assert!(result.contains(&"c@d.com".to_string()));
        assert!(result.contains(&"e@f.com".to_string()));
    }

    #[test]
    fn test_parse_recipients_whitespace() {
        let result = parse_recipients(" a@b.com ,  c@d.com ", " e@f.com ");
        assert_eq!(result.len(), 3);
    }
}
