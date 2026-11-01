use thiserror::Error;

/// Application-wide error type.
///
/// Covers all failure modes across SMTP ingestion, webhook relay, retry scheduling,
/// API authentication, limit enforcement, and auto-reply generation.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("smtp error: {0}")]
    Smtp(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("http client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("dns resolve error: {0}")]
    DnsResolve(String),

    /// D4: an activation code is no longer usable — invalid, expired, or
    /// already redeemed. The *state* (not the message wording) decides the
    /// status: 410 Gone.
    #[error("activation code gone: {0}")]
    ActivationCodeGone(String),

    /// D4: an attachment exceeds the configured size limit → 413.
    #[error("attachment too large: {0}")]
    AttachmentTooLarge(String),

    /// D4: an attachment content type is not allowed → 415.
    #[error("attachment content type not allowed: {0}")]
    AttachmentContentType(String),
}

/// Convenience alias for Result<T, AppError>.
pub type AppResult<T> = Result<T, AppError>;

/// Map AppError to an Axum HTTP status code — the **single exit** for
/// error→status mapping (D4).
///
/// Exhaustive on purpose: there is no `_` catch-all, so adding a variant
/// without declaring its status is a compile error. Handlers and the
/// `IntoResponse` impl must go through this (via [`AppError::status`])
/// instead of inspecting the message string.
pub fn app_error_status(err: &AppError) -> axum::http::StatusCode {
    use axum::http::StatusCode;
    match err {
        AppError::NotFound(_) => StatusCode::NOT_FOUND,
        AppError::Validation(_) | AppError::Config(_) | AppError::BadRequest(_) => {
            StatusCode::BAD_REQUEST
        }
        AppError::Forbidden(_) => StatusCode::FORBIDDEN,
        AppError::Conflict(_) => StatusCode::CONFLICT,
        AppError::ActivationCodeGone(_) => StatusCode::GONE,
        AppError::AttachmentTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
        AppError::AttachmentContentType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        AppError::Database(_)
        | AppError::Io(_)
        | AppError::Smtp(_)
        | AppError::Serde(_)
        | AppError::HttpClient(_)
        | AppError::Internal(_)
        | AppError::Parse(_)
        | AppError::DnsResolve(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl AppError {
    /// D4: the status code for this error — the only sanctioned way to turn
    /// an `AppError` into an HTTP status (delegates to [`app_error_status`]).
    pub fn status(&self) -> axum::http::StatusCode {
        app_error_status(self)
    }
}

/// D4: `AppError` as an axum response — (status, `{"error", "detail"}`), the
/// same body shape the rest of the API uses (`ErrorResponse`).
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = app_error_status(&self);
        let body = axum::Json(serde_json::json!({
            "error": self.variant_name(),
            "detail": Some(self.to_string()),
        }));
        (status, body).into_response()
    }
}

impl AppError {
    /// Stable short name for the JSON `error` field (e.g. `"not_found"`).
    fn variant_name(&self) -> &'static str {
        match self {
            AppError::Database(_) => "database",
            AppError::Io(_) => "io",
            AppError::Config(_) => "config",
            AppError::Smtp(_) => "smtp",
            AppError::Validation(_) => "validation",
            AppError::Serde(_) => "serde",
            AppError::HttpClient(_) => "http_client",
            AppError::NotFound(_) => "not_found",
            AppError::Forbidden(_) => "forbidden",
            AppError::BadRequest(_) => "bad_request",
            AppError::Conflict(_) => "conflict",
            AppError::Internal(_) => "internal",
            AppError::Parse(_) => "parse",
            AppError::DnsResolve(_) => "dns_resolve",
            AppError::ActivationCodeGone(_) => "activation_code_gone",
            AppError::AttachmentTooLarge(_) => "attachment_too_large",
            AppError::AttachmentContentType(_) => "attachment_content_type",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    /// D4 error-status matrix: every `AppError` variant → its status code.
    /// The exhaustive `app_error_status` match guarantees at compile time
    /// that each variant declares a status; this pins the values themselves.
    /// (`HttpClient` has no public constructor and is covered by the
    /// exhaustive match arm → 500.)
    #[test]
    fn d4_error_status_matrix() {
        let cases: Vec<(AppError, StatusCode)> = vec![
            (AppError::Config("x".into()), StatusCode::BAD_REQUEST),
            (AppError::Validation("x".into()), StatusCode::BAD_REQUEST),
            (AppError::BadRequest("x".into()), StatusCode::BAD_REQUEST),
            (AppError::NotFound("x".into()), StatusCode::NOT_FOUND),
            (AppError::Forbidden("x".into()), StatusCode::FORBIDDEN),
            (AppError::Conflict("x".into()), StatusCode::CONFLICT),
            (
                AppError::ActivationCodeGone("already redeemed".into()),
                StatusCode::GONE,
            ),
            (
                AppError::AttachmentTooLarge("25 MB > 20 MB".into()),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                AppError::AttachmentContentType("application/x-msdownload".into()),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                AppError::Database(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                    "/nonexistent/db.sqlite",
                ))),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                AppError::Io(std::io::Error::other("x")),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                AppError::Smtp("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                AppError::Serde(serde_json::from_str::<()>("not json").unwrap_err()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                AppError::Internal("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                AppError::Parse("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                AppError::DnsResolve("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (e, want) in &cases {
            assert_eq!(app_error_status(e), *want, "{e}");
            assert_eq!(e.status(), *want, "{e}");
        }
    }
}
