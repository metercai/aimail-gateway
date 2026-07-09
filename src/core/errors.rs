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
}

/// Convenience alias for Result<T, AppError>.
pub type AppResult<T> = Result<T, AppError>;

/// Map AppError to Axum HTTP status codes for the error handler layer.
pub fn app_error_status(err: &AppError) -> axum::http::StatusCode {
    match err {
        AppError::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
        AppError::Validation(_) => axum::http::StatusCode::BAD_REQUEST,
        AppError::Forbidden(_) => axum::http::StatusCode::FORBIDDEN,
        AppError::Conflict(_) => axum::http::StatusCode::CONFLICT,
        AppError::Config(_) => axum::http::StatusCode::BAD_REQUEST,
        _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
    }
}
