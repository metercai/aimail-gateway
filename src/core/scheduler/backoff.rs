use crate::core::email::storage::EmailRecord;

// ── Backoff calculation ────────────────────────────────────────────

/// Exponential backoff with ±50% jitter: min(initial * multiplier^(attempt-1), max).
pub fn calculate_backoff(
    attempt: u64,
    initial_backoff: u64,
    multiplier: u64,
    max_backoff: u64,
) -> u64 {
    let exp = attempt.saturating_sub(1) as u32;
    let backoff = initial_backoff
        .saturating_mul(multiplier.saturating_pow(exp))
        .min(max_backoff);
    // Add ±50% jitter to spread retry times
    use rand::Rng;
    let jitter = 0.5 + rand::thread_rng().gen::<f64>() * 0.5; // 0.5 .. 1.0
    (backoff as f64 * jitter) as u64
}

// ── Delivery-type detection ────────────────────────────────────────

/// Detect delivery type from direction, headers, or body heuristic.
pub fn detect_delivery_type(record: &EmailRecord) -> &'static str {
    // Direction takes priority: inbound emails ALWAYS go through webhook
    if record.direction == "inbound" {
        return "webhook";
    }

    // For outbound: check headers for explicit delivery_type override
    if let Some(dt) = record.delivery_type_from_headers() {
        match dt.as_str() {
            "smtp" => return "smtp",
            "webhook" => return "webhook",
            _ => {}
        }
    }

    // Heuristic fallback for outbound: if body is present, assume SMTP relay
    if !record.body.is_empty() {
        "smtp"
    } else {
        "webhook"
    }
}
