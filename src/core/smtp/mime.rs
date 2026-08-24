//! MIME helpers for building multipart email bodies and custom headers.

use lettre::message::header::{ContentTransferEncoding, ContentType, Header, HeaderName, HeaderValue};
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
        let name = HeaderName::new_from_ascii(self.name.clone())
            .unwrap_or_else(|_| HeaderName::new_from_ascii("X-AIMail-Agent".to_string()).expect("valid"));
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
