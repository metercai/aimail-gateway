//! Email signature extraction via regex rules.
//!
//! Priority order: RFC 3676 `-- ` → Named closing → Chinese bare signature.

use regex::Regex;
use std::sync::LazyLock;

// ── Rule 1: RFC 3676 dash-dash-space ─────────────────────────────

static SIG_SEP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^-- $").unwrap());

fn extract_rfc3676(body: &str) -> Option<String> {
    let m = SIG_SEP.find(body)?;
    let sig = body[m.end()..].trim().to_string();
    if sig.is_empty() {
        None
    } else {
        Some(sig)
    }
}

// ── Rule 2: Named closing + name/title ───────────────────────────

static NAMED_SIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)(?:Best regards|Sincerely|Regards|Cheers|Thanks|Thank you for|Thank you|此致|敬礼|祝好|谢谢|顺祝商祺).*?[,!]?\s*\n+\s*([^\n]{2,30}(?:\n[^\n]{2,50}){0,4})"
    ).unwrap()
});

fn extract_named_closing(body: &str) -> Option<String> {
    // Search entire body, capture the LAST match — the real signing-off
    // is the final closing phrase, not an incidental one at the top.
    let mut last_caps = None;
    for caps in NAMED_SIG.captures_iter(body) {
        last_caps = Some(caps);
    }
    let caps = last_caps?;
    Some(caps.get(1)?.as_str().trim().to_string())
}

// ── Rule 3: Chinese bare name + company ──────────────────────────

static ZH_SIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)(?:^|\n)([\u{4e00}-\u{9fff}]{2,4})\s*\n([^\n]{0,30}(?:公司|科技|集团|部门|团队)[^\n]{0,20})"
    ).unwrap()
});

fn extract_chinese_bare(body: &str) -> Option<String> {
    // Only check the last 500 characters
    let tail = if body.len() > 500 {
        &body[body.len() - 500..]
    } else {
        body
    };
    let caps = ZH_SIG.captures(tail)?;
    let name = caps.get(1)?.as_str();
    let org = caps.get(2)?.as_str();
    Some(format!("{name} | {org}"))
}

// ── Noise filtering ──────────────────────────────────────────────

static NOISE_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(sent from|get outlook|mobile|iphone|android|本邮件包含|confidential|privacy policy|unsubscribe)"
    ).unwrap()
});

fn clean_signature(sig: &str) -> String {
    let lines: Vec<&str> = sig
        .lines()
        .filter(|l| !NOISE_PATTERNS.is_match(l))
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    // Join with " | " and truncate to 300 chars
    let joined = lines.join(" | ");
    if joined.len() > 300 {
        joined[..300].to_string()
    } else {
        joined
    }
}

// ── Public API ───────────────────────────────────────────────────

/// Extract email signature from body.
/// Returns `(signature_text, confidence)` — confidence: 0.95 (RFC 3676), 0.80 (named closing), 0.65 (Chinese), 0.0 (none).
pub fn extract_signature(body: &str) -> (Option<String>, f64) {
    if body.is_empty() {
        return (None, 0.0);
    }

    // Rule 1: RFC 3676 standard separator → confidence 0.95
    if let Some(sig) = extract_rfc3676(body) {
        let cleaned = clean_signature(&sig);
        if !cleaned.is_empty() {
            return (Some(cleaned), 0.95);
        }
    }

    // Rule 2: Named closing + name/title → confidence 0.80
    if let Some(sig) = extract_named_closing(body) {
        let cleaned = clean_signature(&sig);
        if !cleaned.is_empty() {
            return (Some(cleaned), 0.80);
        }
    }

    // Rule 3: Chinese bare name + company → confidence 0.65
    if let Some(sig) = extract_chinese_bare(body) {
        let cleaned = clean_signature(&sig);
        if !cleaned.is_empty() {
            return (Some(cleaned), 0.65);
        }
    }

    // Rule 4: bare English name + title at end → confidence 0.40
    if let Some(sig) = extract_bare_name_end(body) {
        let cleaned = clean_signature(&sig);
        if !cleaned.is_empty() {
            return (Some(cleaned), 0.40);
        }
    }

    (None, 0.0)
}

fn extract_bare_name_end(body: &str) -> Option<String> {
    // Only if body is reasonably long (skip one-liners)
    if body.len() < 40 {
        return None;
    }
    let lines: Vec<&str> = body.lines().collect();
    if lines.len() < 3 {
        return None;
    }
    // Last non-empty line should look like a title
    let mut last_lines: Vec<&str> = lines.iter()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(3)
        .cloned()
        .collect();
    last_lines.reverse();
    if last_lines.len() < 2 {
        return None;
    }
    let penultimate = last_lines[last_lines.len() - 2].trim();
    let last = last_lines.last().map(|s| s.trim()).unwrap_or("");
    // Name line: 2-30 chars, can't look like a sentence
    if penultimate.len() < 2 || penultimate.len() > 30 {
        return None;
    }
    if penultimate.contains('.') && penultimate.len() > 6 {
        return None; // likely a sentence
    }
    // Title line hint
    let title_hints = ["Engineer", "Manager", "Director", "VP", "CTO", "CEO",
        "Developer", "Designer", "Analyst", "Lead", "Head", "Chief",
        "President", "Specialist", "Coordinator", "Consultant"];
    let has_title = title_hints.iter().any(|h| last.contains(h));
    if !has_title {
        return None;
    }
    Some(format!("{} | {}", penultimate, last))
}

#[cfg(test)]
mod tests {
    use crate::core::email::signature::extract_signature;

    // ═══════════════════════════════════════════════════════════════
    // RFC 3676 standard separator tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rfc3676_english() {
        let body = "Please review the document.\n-- \nJohn Doe\nCTO, Acme Corp\n+1-555-1234";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.9);
        assert!(sig.unwrap().contains("John Doe"));
    }

    #[test]
    fn test_rfc3676_chinese() {
        let body = "请查收附件。\n-- \n李四\n技术总监\n北京科技有限公司\n+86-138-0000-0000";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.9);
        let s = sig.unwrap();
        assert!(s.contains("李四"));
    }

    #[test]
    fn test_rfc3676_multiline_title_company_phone() {
        let body =
            "Here is the report.\n\n-- \nJane Smith\nSenior Software Engineer\nCloud Division\nAcme Corp Inc.\n+1-555-9876\njane@acme.com";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.9);
        let s = sig.unwrap();
        assert!(s.contains("Jane Smith"));
        assert!(s.contains("Acme Corp"));
    }

    #[test]
    fn test_rfc3676_only_signature_no_body() {
        let body = "-- \nJohn Doe\nCEO\nStartup Inc.";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.9);
        let s = sig.unwrap();
        assert!(s.contains("John Doe"));
        assert!(s.contains("Startup Inc"));
    }

    #[test]
    fn test_rfc3676_separator_in_middle() {
        let body = "Main content here.\n-- \nSignature block\nStill more body text below.";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.9);
        let s = sig.unwrap();
        assert!(s.contains("Signature block"));
    }

    #[test]
    fn test_rfc3676_empty_signature_after_separator() {
        let body = "Hello world.\n-- \n";
        let (sig, conf) = extract_signature(body);
        // Empty signature after separator should return None
        assert!(sig.is_none());
        assert_eq!(conf, 0.0);
    }

    // ═══════════════════════════════════════════════════════════════
    // Named closing tests (English)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_named_closing_best_regards() {
        let body = "Please get back to me soon.\n\nBest regards,\nJohn Doe\nProduct Manager";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
        let s = sig.unwrap();
        assert!(s.contains("John Doe"));
    }

    #[test]
    fn test_named_closing_sincerely() {
        let body = "I look forward to hearing from you.\n\nSincerely,\nAlice Johnson\nHR Director";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
        let s = sig.unwrap();
        assert!(s.contains("Alice Johnson"));
    }

    #[test]
    fn test_named_closing_regards() {
        let body = "Thanks for the update.\n\nRegards\nBob\nEngineering";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
        assert!(sig.unwrap().contains("Bob"));
    }

    #[test]
    fn test_named_closing_cheers() {
        let body = "That works for me.\n\nCheers,\nCharlie\n";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
        assert!(sig.unwrap().contains("Charlie"));
    }

    #[test]
    fn test_named_closing_thanks() {
        let body = "Please find attached.\n\nThanks,\nDiana";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
        assert!(sig.unwrap().contains("Diana"));
    }

    #[test]
    fn test_named_closing_cizhi_jingli() {
        let body = "请尽快回复。\n\n此致\n敬礼\n\n张三\nABC科技有限公司";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
    }

    #[test]
    fn test_named_closing_zhuhao() {
        let body = "期待您的回复。\n祝好\n\n王五\n市场部";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
    }

    #[test]
    fn test_named_closing_xiexie() {
        let body = "麻烦您了。\n谢谢\n\n赵六";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
        assert!(sig.unwrap().contains("赵六"));
    }

    #[test]
    fn test_named_closing_shunzhu_shangqi() {
        let body = "以上是本月报告。\n顺祝商祺\n\n钱七\n销售总监\nXYZ贸易集团";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.75);
    }

    // ═══════════════════════════════════════════════════════════════
    // Chinese bare signature tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_chinese_bare_name_company() {
        let body = "这是会议纪要，请查收。\n\n张三\nABC科技有限公司";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.6);
        let s = sig.unwrap();
        assert!(s.contains("张三"));
        assert!(s.contains("ABC科技"));
    }

    #[test]
    fn test_chinese_bare_name_jituan() {
        let body = "汇报完毕。\n李四\n腾讯集团";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(conf > 0.6);
        let s = sig.unwrap();
        assert!(s.contains("李四"));
        assert!(s.contains("腾讯集团"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Noise filtering tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_noise_mobile_filtered() {
        let body = "Thanks.\n-- \nJohn\nSent from my iPhone";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        let s = sig.unwrap();
        assert!(!s.contains("iPhone"));
        assert!(s.contains("John"));
    }

    #[test]
    fn test_noise_confidential_filtered() {
        let body = "Here is the data.\n-- \nSarah\nConfidential - Do Not Forward\nsarah@corp.com";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        let s = sig.unwrap();
        assert!(!s.to_lowercase().contains("confidential"));
        assert!(s.contains("Sarah"));
    }

    #[test]
    fn test_noise_unsubscribe_filtered() {
        let body =
            "Newsletter content.\n-- \nThe Team\nUnsubscribe here: http://example.com/optout";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        let s = sig.unwrap();
        assert!(!s.to_lowercase().contains("unsubscribe"));
    }

    // ═══════════════════════════════════════════════════════════════
    // No signature tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_no_signature_plain_text() {
        let body = "Just a plain message with no signature.";
        let (sig, _conf) = extract_signature(body);
        assert!(sig.is_none());
    }

    #[test]
    fn test_no_signature_empty_body() {
        let body = "";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_none());
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn test_no_signature_whitespace_only() {
        let body = "   \n  \n   ";
        let (sig, _conf) = extract_signature(body);
        assert!(sig.is_none());
    }

    #[test]
    fn test_no_signature_code_block() {
        let body =
            "fn main() {\n    println!(\"Hello\");\n}\n-- this is a comment\nnot a signature";
        let (sig, _conf) = extract_signature(body);
        // "-- " must be on its own line (^-- $), not "-- this"
        assert!(sig.is_none());
    }

    // ═══════════════════════════════════════════════════════════════
    // Priority tests: RFC 3676 wins over named closing
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rfc3676_priority_over_closing() {
        let body = "Main text.\nBest regards,\nJohn\n-- \nJane Doe\nCTO\nAcme Corp";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some());
        assert!(
            conf > 0.9,
            "RFC 3676 should win with confidence > 0.9, got {conf}"
        );
        let s = sig.unwrap();
        assert!(s.contains("Jane Doe"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Edge case: long signature truncation
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_named_closing_thank_you_for() {
        let body = "Content.\n\nThank you for choosing HSBC,\n\nSimang Daimari\nInternational Onboarding";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some(), "'Thank you for' should match named closing");
        assert!(conf > 0.7);
        let s = sig.unwrap();
        assert!(s.contains("Simang Daimari"));
        assert!(s.contains("International Onboarding"));
    }

    #[test]
    fn test_long_signature_truncation() {
        let long_line = "A".repeat(400);
        let body = format!("Text.\n-- \n{long_line}");
        let (sig, conf) = extract_signature(&body);
        assert!(sig.is_some());
        assert!(conf > 0.9);
        let s = sig.unwrap();
        assert!(s.len() <= 300);
    }

    #[test]
    fn test_disclaimer_then_sig() {
        // Disclaimer text before --, signature after. Both should survive.
        let body = "Body text.\n\nThis email is CONFIDENTIAL.\nRESTRICTED.\n\n-- \nJane Smith\nLegal Dept";
        let (sig, conf) = extract_signature(body);
        assert!(sig.is_some(), "'-- ' sig should be found after disclaimer text");
        assert!((conf - 0.95).abs() < 0.01, "RFC 3676 confidence expected 0.95");
        assert!(sig.unwrap().contains("Jane Smith"));
    }
}

