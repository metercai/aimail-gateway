//! MIME helpers for building multipart email bodies and custom headers.

use lettre::message::header::{
    ContentTransferEncoding, ContentType, Header, HeaderName, HeaderValue,
};
use lettre::message::{Body, MultiPart, SinglePart};
use lettre::Address;

use crate::core::errors::{AppError, AppResult};

// ── Custom header types ─────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct ContentDispositionRaw(pub(crate) String);

impl Header for ContentDispositionRaw {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("Content-Disposition")
    }
    fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self(s.into()))
    }
    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), self.0.clone())
    }
}

#[derive(Clone)]
pub(crate) struct ContentTransferEncodingRaw(pub(crate) String);

impl Header for ContentTransferEncodingRaw {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("Content-Transfer-Encoding")
    }
    fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self(s.into()))
    }
    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), self.0.clone())
    }
}

/// Parse a single `user@domain` (optionally `Name <user@domain>`) into a
/// lettre mailbox. Used for the record-level `reply-to` header: unlike the
/// passthrough whitelist it is a real RFC 5322 field, so it goes through the
/// typed builder rather than a raw header. Unparsable values are dropped by
/// the caller (never a send failure).
pub(crate) fn parse_mailbox(raw: &str) -> Option<lettre::message::Mailbox> {
    let s = raw.trim();
    let (name, addr) = match (s.find('<'), s.find('>')) {
        (Some(a), Some(b)) if b > a + 1 => {
            let n = s[..a].trim().trim_matches('"').trim();
            (
                Some(n.to_string()).filter(|n| !n.is_empty()),
                s[a + 1..b].trim(),
            )
        }
        _ => (None, s),
    };
    let (user, domain) = addr.split_once('@')?;
    if user.is_empty() || !domain.contains('.') || addr.contains(char::is_whitespace) {
        return None;
    }
    let address = Address::new(user, domain).ok()?;
    Some(lettre::message::Mailbox::new(name, address))
}

/// Generic outbound passthrough header (X-AIMail-Agent,
/// X-Board-Members, X-AIMail-AutoReply). Built from a header name +
/// value pair; used by mx_deliverer and relay sender so custom headers
/// stored in the record survive onto external SMTP mail.
#[derive(Clone)]
pub(crate) struct PassthroughHeader {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl Header for PassthroughHeader {
    fn name() -> HeaderName {
        // Never used directly — instances carry their own name via display().
        HeaderName::new_from_ascii_str("X-AIMail-Agent")
    }
    fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            name: "X-AIMail-Agent".into(),
            value: s.into(),
        })
    }
    fn display(&self) -> HeaderValue {
        let name = HeaderName::new_from_ascii(self.name.clone()).unwrap_or_else(|_| {
            HeaderName::new_from_ascii("X-AIMail-Agent".to_string()).expect("valid")
        });
        HeaderValue::new(name, self.value.clone())
    }
}

// ── Helpers ────────────────────────────────────────────────────

/// Build a `multipart/mixed` MIME envelope wrapping the text body and
/// base64-encoded attachment parts.
pub(crate) fn build_with_attachments(
    alt_part: MultiPart,
    attachments: &[(String, String, Vec<u8>)],
) -> MultiPart {
    let mut mixed = MultiPart::mixed().multipart(alt_part);

    for (filename, content_type, data) in attachments {
        let content_type_str = if content_type.is_empty() {
            format!("application/octet-stream; name=\"{}\"", filename)
        } else {
            format!("{}; name=\"{}\"", content_type, filename)
        };

        let disposition = format!("attachment; filename=\"{}\"", filename);

        let part = SinglePart::builder()
            .header(
                content_type_str
                    .parse::<ContentType>()
                    .unwrap_or(ContentType::TEXT_PLAIN),
            )
            .header(ContentDispositionRaw(disposition))
            .header(ContentTransferEncodingRaw("base64".to_string()))
            // AUDIT-1 P2-11 (smtp_sender verify): let lettre do the base64
            // encoding. Previously we pre-encoded AND declared base64, so
            // lettre encoded again → double-encoded attachment bodies.
            .body(
                Body::new_with_encoding(data.to_vec(), ContentTransferEncoding::Base64)
                    .expect("base64 body encoding"),
            );

        mixed = mixed.singlepart(part);
    }

    mixed
}

/// Parse an email address string into a lettre `Address`.
pub(crate) fn parse_address(addr: &str) -> AppResult<Address> {
    addr.parse::<Address>()
        .map_err(|e| AppError::Validation(format!("invalid email address '{}': {}", addr, e)))
}

#[cfg(test)]
mod tests {
    use super::parse_mailbox;

    #[test]
    fn bare_address_parses() {
        let mb = parse_mailbox("activate@mail.example.com").expect("bare address");
        assert_eq!(mb.email.to_string(), "activate@mail.example.com");
        assert!(mb.name.is_none());
    }

    #[test]
    fn name_form_parses() {
        let mb = parse_mailbox("AIMail Activation <activate@mail.example.com>").unwrap();
        assert_eq!(mb.email.to_string(), "activate@mail.example.com");
        assert_eq!(mb.name.as_deref(), Some("AIMail Activation"));
    }

    #[test]
    fn invalid_values_are_rejected() {
        for bad in [
            "",
            "no-at-sign",
            "user@",
            "@domain.test",
            "a b@c.test",
            "<>",
        ] {
            assert!(parse_mailbox(bad).is_none(), "must reject {bad:?}");
        }
    }
}
