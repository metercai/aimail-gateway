use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use ipnetwork::IpNetwork;
use sha2::Sha256;

/// Compute the raw HMAC-SHA256 hex digest for a message.
fn compute_hmac_hex(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Generate HMAC-SHA256 signature for webhook delivery.
/// Returns `(hex_signature, timestamp_ms)`. Compatible with Hermes webhook adapter.
pub fn sign_payload(secret: &[u8], payload: &[u8]) -> (String, u64) {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let signature_hex = compute_hmac_hex(secret, payload);

    (signature_hex, timestamp_ms)
}

/// Strip persona prefix from an email local-part.
/// `persona.profile@domain` → `(profile@domain, persona)`, otherwise addr unchanged.
pub fn strip_persona(address: &str) -> (String, String) {
    let lower = address.to_lowercase();
    let (local, domain) = match lower.split_once('@') {
        Some(parts) => parts,
        None => return (address.to_string(), String::new()),
    };
    match local.split_once('.') {
        Some((persona, profile)) if !persona.is_empty() && !profile.is_empty() => {
            (format!("{}@{}", profile, domain), persona.to_string())
        }
        _ => (address.to_string(), String::new()),
    }
}

/// Detect if text contains CJK characters (unified ideographs + CJK
/// punctuation + fullwidth forms). Same ranges as the advanced-edition
/// notification templates; shared here so both base and advanced can reuse it.
pub fn has_cjk(text: &str) -> bool {
    text.chars()
        .any(|c| matches!(c, '\u{4e00}'..='\u{9fff}' | '\u{3000}'..='\u{303f}' | '\u{ff00}'..='\u{ffef}'))
}

/// Check if an IP address is within any of the allowed CIDRs.
pub fn is_ip_in_cidrs(ip_str: &str, cidrs: &[String]) -> bool {
    if cidrs.is_empty() {
        return true; // Empty whitelist means allow all
    }

    let ip = match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    cidrs.iter().any(|cidr| {
        if let Ok(network) = cidr.parse::<IpNetwork>() {
            network.contains(ip)
        } else {
            false
        }
    })
}

// ── HTML/Markdown conversion ───────────────────────────────────────

/// Convert HTML content to Markdown (simple heuristic).
pub fn html_to_markdown(html: &str) -> String {
    let mut result = html.to_string();

    // Remove script/style blocks
    result = regex::Regex::new(r"<script[^>]*>.*?</script>")
        .unwrap()
        .replace_all(&result, "")
        .to_string();
    result = regex::Regex::new(r"<style[^>]*>.*?</style>")
        .unwrap()
        .replace_all(&result, "")
        .to_string();

    // Headings → markdown headings (must happen BEFORE block element stripping)
    for (level, prefix) in [
        ("h1", "# "),
        ("h2", "## "),
        ("h3", "### "),
        ("h4", "#### "),
        ("h5", "##### "),
        ("h6", "###### "),
    ] {
        result = regex::Regex::new(&format!(r"<{level}[^>]*>(.*?)</{level}>"))
            .unwrap()
            .replace_all(&result, &format!("{}$1", prefix))
            .to_string();
    }

    // Block elements → double newline
    for tag in &["p", "div", "ul", "ol", "table", "tr"] {
        result = result.replace(&format!("<{tag}>"), "\n\n");
        result = result.replace(&format!("<{tag} "), "\n\n");
        result = result.replace(&format!("</{tag}>"), "\n");
    }

    // List items → "- "
    result = regex::Regex::new(r"<li[^>]*>(.*?)</li>")
        .unwrap()
        .replace_all(&result, "- $1\n")
        .to_string();

    // Inline: <code> → backticks
    result = regex::Regex::new(r"<code[^>]*>(.*?)</code>")
        .unwrap()
        .replace_all(&result, "`$1`")
        .to_string();

    // Inline elements
    result = regex::Regex::new(r"<b[^>]*>(.*?)</b>")
        .unwrap()
        .replace_all(&result, "**$1**")
        .to_string();
    result = regex::Regex::new(r"<strong[^>]*>(.*?)</strong>")
        .unwrap()
        .replace_all(&result, "**$1**")
        .to_string();
    result = regex::Regex::new(r"<i[^>]*>(.*?)</i>")
        .unwrap()
        .replace_all(&result, "*$1*")
        .to_string();
    result = regex::Regex::new(r"<em[^>]*>(.*?)</em>")
        .unwrap()
        .replace_all(&result, "*$1*")
        .to_string();
    result = regex::Regex::new(r#"<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>"#)
        .unwrap()
        .replace_all(&result, "[$2]($1)")
        .to_string();
    result = regex::Regex::new(r"<br\s*/?>")
        .unwrap()
        .replace_all(&result, "\n")
        .to_string();

    // Strip remaining HTML tags
    result = regex::Regex::new(r"<[^>]+>")
        .unwrap()
        .replace_all(&result, "")
        .to_string();

    // Decode common HTML entities
    result = result.replace("&lt;", "<");
    result = result.replace("&gt;", ">");
    result = result.replace("&amp;", "&");
    result = result.replace("&quot;", "\"");
    result = result.replace("&apos;", "'");
    result = result.replace("&nbsp;", " ");

    // Collapse multiple blank lines
    result = regex::Regex::new(r"\n{3,}")
        .unwrap()
        .replace_all(&result, "\n\n")
        .to_string();

    result.trim().to_string()
}

/// Convert Markdown to HTML: headers, bold, italic, links, code, lists, paragraphs.
pub fn markdown_to_html(markdown: &str) -> String {
    let mut result = markdown.to_string();

    // Escape HTML entities
    result = result.replace("&", "&amp;");
    result = result.replace("<", "&lt;");
    result = result.replace(">", "&gt;");

    // Headers (must be before paragraphs)
    result = regex::Regex::new(r"^###### (.+)$")
        .unwrap()
        .replace_all(&result, "<h6>$1</h6>")
        .to_string();
    result = regex::Regex::new(r"^##### (.+)$")
        .unwrap()
        .replace_all(&result, "<h5>$1</h5>")
        .to_string();
    result = regex::Regex::new(r"^#### (.+)$")
        .unwrap()
        .replace_all(&result, "<h4>$1</h4>")
        .to_string();
    result = regex::Regex::new(r"^### (.+)$")
        .unwrap()
        .replace_all(&result, "<h3>$1</h3>")
        .to_string();
    result = regex::Regex::new(r"^## (.+)$")
        .unwrap()
        .replace_all(&result, "<h2>$1</h2>")
        .to_string();
    result = regex::Regex::new(r"^# (.+)$")
        .unwrap()
        .replace_all(&result, "<h1>$1</h1>")
        .to_string();

    // Bold + Italic
    result = regex::Regex::new(r"\*\*\*(.+?)\*\*\*")
        .unwrap()
        .replace_all(&result, "<strong><em>$1</em></strong>")
        .to_string();
    result = regex::Regex::new(r"\*\*(.+?)\*\*")
        .unwrap()
        .replace_all(&result, "<strong>$1</strong>")
        .to_string();
    result = regex::Regex::new(r"\*(.+?)\*")
        .unwrap()
        .replace_all(&result, "<em>$1</em>")
        .to_string();

    // Links
    result = regex::Regex::new(r"\[([^\]]+)\]\(([^)]+)\)")
        .unwrap()
        .replace_all(&result, "<a href=\"$2\">$1</a>")
        .to_string();

    // Inline code
    result = regex::Regex::new(r"`([^`]+)`")
        .unwrap()
        .replace_all(&result, "<code>$1</code>")
        .to_string();

    // Unordered list items
    result = regex::Regex::new(r"^- (.+)$")
        .unwrap()
        .replace_all(&result, "<li>$1</li>")
        .to_string();
    result = regex::Regex::new(r"^\* (.+)$")
        .unwrap()
        .replace_all(&result, "<li>$1</li>")
        .to_string();

    // Wrap consecutive <li> in <ul>
    result = regex::Regex::new(r"((?:<li>.*?</li>\n?)+)")
        .unwrap()
        .replace_all(&result, "<ul>$1</ul>")
        .to_string();

    // Horizontal rule
    result = regex::Regex::new(r"^---+$")
        .unwrap()
        .replace_all(&result, "<hr>")
        .to_string();

    // Paragraphs: wrap lines that aren't already HTML tags
    let lines: Vec<String> = result
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                String::new()
            } else if trimmed.starts_with('<') {
                line.to_string()
            } else {
                format!("<p>{}</p>", line)
            }
        })
        .collect();

    result = lines.join("\n");

    // Collapse multiple blank lines
    result = regex::Regex::new(r"\n{3,}")
        .unwrap()
        .replace_all(&result, "\n\n")
        .to_string();

    result.trim().to_string()
}
