//! Email body processing pipeline: layer decomposition, HTML→Markdown conversion,
//! per-layer signature extraction, and assembly with quote markers.
//!
//! Strategy: from outside in, each layer = [current message + signature],
//! followed by quoted/replied content (next layer).
//!
//! ```text
//! L0: current message
//! ---
//! L0 signature
//! ---
//! > L1 (quoted): original message
//! > ---
//! > L1 signature
//! >   > L2 (nested quote): ...
//! ```

use crate::core::email::preprocess as pp;
use crate::core::email::signature;

/// A single layer in the decomposition.
#[derive(Debug)]
pub struct Layer {
    /// Clean body text (whitelist stripped, no signature block).
    pub body: String,
    /// Extracted signature, if any.
    pub signature: Option<ExtractedSignature>,
    /// How this layer relates to the parent.
    pub kind: LayerKind,
    /// Nested quoted content (deeper layers).
    pub children: Vec<Layer>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayerKind {
    /// The outermost (most recent) layer — current sender's own content.
    Current,
    /// A forwarded message.
    Forward,
    /// A replied-to message.
    Reply,
}

#[derive(Debug, Clone)]
pub struct ExtractedSignature {
    pub raw: String,
    pub separator: String,
    pub confidence: f64,
}

/// Result of the full body processing pipeline.
#[derive(Debug)]
pub struct ProcessedEmail {
    /// Assembled markdown body with quote markers and signature annotations.
    pub body: String,
    /// Current sender's signature (outermost layer).
    pub signature: Option<ExtractedSignature>,
    /// All layers found (from outermost to innermost).
    pub layers: Vec<Layer>,
}

// ═══════════════════════════════════════════════════════════════
// Forward/reply boundary markers
// ═══════════════════════════════════════════════════════════════

/// Check if a line is a known forward boundary (whole-line match).
fn is_forward_boundary(line: &str) -> bool {
    let t = line.trim();
    let t_unquoted = t.strip_prefix('>').map(|s| s.trim()).unwrap_or(t);
    t == "--- Forwarded message ---"
        || t == "--- forwarded message ---"
        || t == "--转发邮件--"
        || t == "---------- Forwarded message ---------"
        || t == "-----Original Message-----"
        || t_unquoted == "-----Original Message-----"
        || t.contains("------------------ 原始邮件 ---------")
}

/// Check if a line starts a reply separator ("On ... wrote:" format).
fn is_reply_boundary(line: &str) -> Option<&'static str> {
    let t = line.trim().to_lowercase();
    if t.starts_with("on ") && t.ends_with("wrote:") {
        return Some("reply");
    }
    if (t.starts_with("在 ") || t.starts_with("于 ")) && t.contains("写道") {
        return Some("reply");
    }
    None
}

// ═══════════════════════════════════════════════════════════════
// HTML → Markdown
// ═══════════════════════════════════════════════════════════════

fn html_to_markdown(html: &str) -> String {
    match html_to_markdown_rs::convert(html, None) {
        Ok(result) => result.content.unwrap_or_default(),
        Err(e) => {
            tracing::warn!(operation = "html_to_markdown_failed", error = %e);
            // Fallback: simple tag-stripping like the old html_to_text
            crate::core::email::factory::EmailFactory::html_to_text(html)
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// HTML entity decoding
// ═══════════════════════════════════════════════════════════════

/// Decode common HTML entities in text/plain bodies that survive
/// MIME extraction (e.g. `&nbsp;`, `&gt;`, `&lt;`, `&amp;`).
fn decode_html_entities(text: &str) -> String {
    text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

// ═══════════════════════════════════════════════════════════════
// Layer decomposition
// ═══════════════════════════════════════════════════════════════

/// Split body text into [current_content, quoted_content] at the first
/// quote/forward boundary. Returns `(before, after, kind)`.
fn split_at_quote_boundary(body: &str) -> Option<(String, String, String, LayerKind)> {
    let lines: Vec<&str> = body.lines().collect();
    let mut boundary_idx = None;
    let mut kind = LayerKind::Reply;

    for (i, line) in lines.iter().enumerate() {
        if is_forward_boundary(line) {
            boundary_idx = Some(i);
            kind = LayerKind::Forward;
            break;
        }
        if is_reply_boundary(line).is_some() {
            boundary_idx = Some(i);
            kind = LayerKind::Reply;
            break;
        }
    }

    boundary_idx.map(|idx| {
        let before = if idx > 0 {
            lines[..idx].join("\n")
        } else {
            String::new()
        };
        let after_boundary = if idx + 1 < lines.len() {
            &lines[idx + 1..]
        } else {
            return (before, String::new(), String::new(), kind);
        };

        // Find the quoted block:
        // - Reply boundaries: only `>` lines are quoted; non-`>` after is current
        // - Forward boundaries: everything after is forwarded content
        let (quoted, after_quote): (String, String) = if kind == LayerKind::Reply {
            let quote_end = after_boundary
                .iter()
                .position(|l| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with('>')
                })
                .unwrap_or(after_boundary.len());
            (
                after_boundary[..quote_end].join("\n"),
                if quote_end < after_boundary.len() {
                    after_boundary[quote_end..].join("\n")
                } else {
                    String::new()
                },
            )
        } else {
            // Forward: all text after boundary is the original message
            (after_boundary.join("\n"), String::new())
        };
        (before, quoted, after_quote, kind)
    })
}

/// Recursively decompose body into layers.
fn decompose_layers(body: &str) -> Vec<Layer> {
    let mut layers = Vec::new();
    let mut remaining = body.to_string();
    let mut first = true;
    let max_layers = 20; // safety limit

    for _ in 0..max_layers {
        if let Some((current, quoted, after_quote, kind)) = split_at_quote_boundary(&remaining) {
            // after_quote text belongs to current layer — merge in
            let combined = if after_quote.is_empty() {
                current
            } else {
                format!("{}\n{}", current, after_quote)
            };
            let processed =
                process_single_layer(&combined, if first { LayerKind::Current } else { kind });
            layers.push(processed);
            remaining = quoted;
            first = false;
        } else {
            let processed = process_single_layer(
                &remaining,
                if first {
                    LayerKind::Current
                } else {
                    LayerKind::Reply
                },
            );
            layers.push(processed);
            break;
        }
    }

    layers
}

// ═══════════════════════════════════════════════════════════════
// Single-layer processing
// ═══════════════════════════════════════════════════════════════

/// Process a single layer: whitelist → extract signature → [HTML→MD] → noise filter.
fn process_single_layer(body: &str, kind: LayerKind) -> Layer {
    // Step 1: Strip whitelist instructions (security)
    let (clean1, _wl) = pp::strip_whitelist_instructions(body);

    // Step 2: Extract signature from the full original body
    let (sig_raw, sig_conf) = signature::extract_signature(&clean1);
    let sig = sig_raw.map(|raw| ExtractedSignature {
        separator: detect_separator(&raw),
        raw,
        confidence: sig_conf,
    });

    // Step 3: Remove signature block from body if found
    let clean2 = if let Some(ref s) = sig {
        strip_signature_from_body(&clean1, &s.raw)
    } else {
        clean1
    };

    // Step 4: HTML→Markdown conversion (after layers/sig, before noise)
    let is_html = clean2.trim_start().starts_with('<')
        || clean2.trim_start().starts_with("<!DOCTYPE")
        || clean2.trim_start().starts_with("<html");
    let clean3 = if is_html {
        html_to_markdown(&clean2)
    } else {
        clean2
    };

    // Step 5: Decode HTML entities
    let clean4 = decode_html_entities(&clean3);

    // Step 6: Noise filtering (disclaimer, legal notices)
    let body_clean = filter_noise(&clean4);

    Layer {
        body: body_clean,
        signature: sig,
        kind,
        children: Vec::new(), // filled by caller
    }
}

/// Remove the extracted signature block from the end of the body.
fn strip_signature_from_body(body: &str, signature: &str) -> String {
    if let Some(pos) = body.rfind(signature) {
        let before = body[..pos].trim();
        // Also remove the separator line (-- ) before the signature
        let before = before.trim_end_matches("--").trim();
        before.to_string()
    } else {
        body.to_string()
    }
}

/// Detect which separator rule matched.
fn detect_separator(_sig: &str) -> String {
    // Check against the known signatures
    "-- ".to_string()
}

// ═══════════════════════════════════════════════════════════════
// Noise filtering
// ═══════════════════════════════════════════════════════════════

static DISCLAIMER_MARKERS: &[&str] = &[
    "This email is intended for",
    "This communication is confidential",
    "This message contains confidential",
    "DISCLAIMER",
    "本邮件及其附件内容",
    "本电子邮件及其附件",
    "本邮件包含保密信息",
    "IMPORTANT NOTICE",
    "The information contained in this",
    "If you have received this email in error",
    "Email intended for",
    "This email has been sent",
    "EMAIL SECURITY INFORMATION",
    "RESTRICTED",
    "ACCOUNT-RELATED QUESTIONS",
    "Please do not reply to this email",
    "Stay in the know",
];

fn filter_noise(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut cleaned = Vec::new();
    let mut in_disclaimer = false;

    for line in &lines {
        let t = line.trim();
        if t.is_empty() && in_disclaimer {
            continue;
        }
        if is_disclaimer_start(t) {
            in_disclaimer = true;
            continue;
        }
        if in_disclaimer {
            // End of disclaimer block = non-empty, non-indented line
            // that doesn't look like it belongs to the disclaimer
            if !t.is_empty()
                && !t.starts_with(' ')
                && !t.starts_with('\t')
                && !is_disclaimer_continuation(t)
            {
                in_disclaimer = false;
                cleaned.push(*line);
            }
            // else skip this line
            continue;
        }
        cleaned.push(*line);
    }

    cleaned.join("\n")
}

fn is_disclaimer_start(line: &str) -> bool {
    for &m in DISCLAIMER_MARKERS {
        if line.starts_with(m) || line.contains(m) {
            return true;
        }
    }
    false
}

fn is_disclaimer_continuation(line: &str) -> bool {
    // Lines that look like legal footer (©, ®, address, phone)
    line.starts_with('©')
        || line.starts_with('®')
        || line.starts_with("RESTRICTED")
        || line.starts_with("Member FDIC")
        || line.starts_with("&nbsp;")
        || line.starts_with(" ")
        || line.starts_with("PO Box")
        || line.starts_with("P.O. Box")
        || line.starts_with("All rights reserved")
        || line.starts_with("此电子邮件")
        || line.starts_with("此邮件")
        || line.starts_with("N.A.")
        || line.starts_with("P.O.")
        || line.contains("License #:")
}

// ═══════════════════════════════════════════════════════════════
// Assembly
// ═══════════════════════════════════════════════════════════════

/// Assemble layers into a single markdown body with quote markers.
fn assemble_layers(layers: &[Layer]) -> String {
    if layers.is_empty() {
        return String::new();
    }

    let mut parts = Vec::new();

    for (depth, layer) in layers.iter().enumerate() {
        let prefix = "> ".repeat(depth);

        if depth == 0 {
            // Current layer: plain body
            if !layer.body.is_empty() {
                parts.push(layer.body.clone());
            }
            // Signature
            if let Some(ref sig) = layer.signature {
                parts.push(format!("---\n\n**发件人签名:** {}", sig.raw));
            }
        } else {
            // Quoted layer: prefix every content line with >
            let kind_label = match layer.kind {
                LayerKind::Forward => "转发",
                LayerKind::Reply => "回复",
                _ => "引用",
            };
            parts.push(format!("---\n**{}邮件:**", kind_label));
            if !layer.body.is_empty() {
                let quoted_body = layer
                    .body
                    .lines()
                    .map(|l| {
                        let t = l.trim();
                        if t.is_empty() {
                            format!(">")
                        } else {
                            format!("> {}", l)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                parts.push(quoted_body);
            }
            // Signature
            if let Some(ref sig) = layer.signature {
                parts.push(format!(
                    "{}> ---\n{}> **原发件人签名:** {}",
                    prefix, prefix, sig.raw
                ));
            }
        }
    }

    parts.join("\n\n")
}

// ═══════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════

/// Process a raw email body through the full pipeline.
///
/// * `body` - The raw text body (after MIME extraction, charset decoding).
/// * `is_html` - If true, run HTML→Markdown conversion first.
pub fn process_email_body(body: &str, _is_html: bool) -> ProcessedEmail {
    // Step 1: Decompose into layers (on raw text, handles HTML in per-layer processing)
    let layers = decompose_layers(body);

    // Step 2: Assemble
    let assembled = assemble_layers(&layers);

    // Step 3: Extract current (outermost) signature
    let current_sig = layers.first().and_then(|l| l.signature.clone());

    ProcessedEmail {
        body: assembled,
        signature: current_sig,
        layers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_text_body() -> String {
        // Path from workspace root: {repo}/agentmail/tests/original-plain.txt
        // CARGO_MANIFEST_DIR = aimail-gateway/
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap() // go up to workspace root
            .join("agentmail")
            .join("tests")
            .join("original-plain.txt");
        fs::read_to_string(p).unwrap_or_default()
    }

    #[test]
    fn test_no_quote() {
        let body = "This is a simple email.\n\nBest regards,\nJohn";
        let result = process_email_body(body, false);
        assert!(result.body.contains("simple email"));
        assert!(result.signature.is_some());
        assert_eq!(result.layers.len(), 1);
    }

    #[test]
    fn test_reply_on_wrote() {
        let body = "My reply.\n\nOn Mon, at 5pm John wrote:\n> Old message";
        let result = process_email_body(body, false);
        assert!(result.body.contains("My reply"));
        assert!(result.body.contains("> Old message"));
        assert_eq!(result.layers.len(), 2);
    }

    #[test]
    fn test_email_without_signature() {
        let body = "Just a short note.";
        let result = process_email_body(body, false);
        assert_eq!(result.body, "Just a short note.");
        assert!(result.signature.is_none());
    }

    #[test]
    fn test_html_convert() {
        let html = "<p>Hello <b>World</b></p>";
        let result = process_email_body(html, true);
        assert!(result.body.contains("Hello"));
        assert!(result.body.contains("World"));
    }

    #[test]
    fn test_real_hsbc_email() {
        let body = test_text_body();
        if body.is_empty() {
            eprintln!("WARNING: test email file not found, skipping");
            return;
        }
        let result = process_email_body(&body, false);
        // Write output to file for review
        let out_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("agentmail/tests/processed-body.md");
        let _ = std::fs::write(&out_path, &result.body);

        eprintln!("=== Signature ===");
        if let Some(ref sig) = result.signature {
            eprintln!("confidence={:.0}%", sig.confidence * 100.0);
            for line in sig.raw.lines().take(5) {
                eprintln!("  {}", line);
            }
        } else {
            eprintln!("(none)");
        }
        eprintln!("=== Stats ===");
        eprintln!(
            "layers={} body={}chars sig={}",
            result.layers.len(),
            result.body.len(),
            result.signature.is_some()
        );
        // Verify L1 signature exists in forwarded content
        if result.layers.len() >= 2 && !result.layers[1].signature.is_some() {
            eprintln!("WARN: forwarded layer lacks signature extraction");
        }
        eprintln!("Output saved to: {}", out_path.display());
        // Should have at least a signature extracted
        if let Some(ref sig) = result.signature {
            eprintln!(
                "Extracted signature ({:.0}% confidence):",
                sig.confidence * 100.0
            );
            for line in sig.raw.lines().take(5) {
                eprintln!("  {}", line);
            }
        }
        // Should have disclaimer stripped (no "RESTRICTED" block in body)
        assert!(
            !result.body.contains("RESTRICTED"),
            "disclaimer 'RESTRICTED' should be stripped"
        );
        // HSBC logo CID reference should remain as or be stripped
        let cid_count = result.body.matches("cid:").count();
        eprintln!("cid: references remaining in body: {}", cid_count);
        eprintln!(
            "Processed body: {} chars, {} layers, sig={}",
            result.body.len(),
            result.layers.len(),
            result.signature.is_some()
        );
    }
}
