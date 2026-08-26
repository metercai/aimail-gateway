//! Attachment upload and download handlers.

use axum::{
    body::Body,
    extract::{Extension, Multipart, Path, State},
    http::StatusCode,
    response::Json,
    response::Response,
};
use tracing::info;
use uuid::Uuid;

use crate::core::api::auth::require_scope;
use crate::core::api::types::*;
use crate::core::email::factory::AttachmentFactory;
use crate::core::storage::ApiKeyRecord;

/// POST /api/v1/upload — Upload an attachment for outbound email.
pub async fn upload_attachment(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadAttachmentResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_scope(&api_key, "agent")?;

    // ── Parse multipart field ──
    let field = loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_string();
                if name == "file" {
                    break field;
                }
                // Skip non-file fields
            }
            Ok(None) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "No file uploaded".to_string(),
                        detail: Some("Expected a multipart field named 'file'".to_string()),
                    }),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid multipart data".to_string(),
                        detail: Some(e.to_string()),
                    }),
                ));
            }
        }
    };

    let filename = field
        .file_name()
        .unwrap_or("unknown")
        .to_string()
        .replace(|c: char| c.is_whitespace(), "_");
    let content_type = field
        .content_type()
        .unwrap_or("application/octet-stream")
        .to_string();

    let data = match field.bytes().await {
        Ok(data) => data,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Failed to read file data".to_string(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    };

    let attachment_id = Uuid::new_v4().to_string();

    // Use AttachmentFactory::save_attachment with mail_id="" and recipient=email_address
    match state
        .factories
        .attachment
        .save_attachment(
            &state.config.storage,
            &api_key.email_address,
            &attachment_id,
            &filename,
            &content_type,
            &data,
            "",
            &api_key.email_address,
        )
        .await
    {
        Ok(record) => {
            state.metrics.inc_attachments_uploaded();
            info!(
                operation = "attachment_uploaded",
                attachment_id = %record.id,
                filename = %record.filename,
                system_id = %api_key.system_id,
                "Attachment uploaded"
            );
            Ok((
                StatusCode::CREATED,
                Json(UploadAttachmentResponse {
                    attachment_id: record.id.clone(),
                    filename: record.filename.clone(),
                    content_type: record.content_type.clone().unwrap_or_default(),
                }),
            ))
        }
        Err(e) => {
            let status = match &e {
                crate::core::errors::AppError::Validation(msg) => {
                    if msg.contains("exceeds max size") {
                        StatusCode::PAYLOAD_TOO_LARGE
                    } else if msg.contains("content type") {
                        StatusCode::UNSUPPORTED_MEDIA_TYPE
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            let error_msg = match status {
                StatusCode::PAYLOAD_TOO_LARGE => "Attachment too large".to_string(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE => "Content type not allowed".to_string(),
                _ => "Failed to save attachment".to_string(),
            };
            Err((
                status,
                Json(ErrorResponse {
                    error: error_msg,
                    detail: Some(e.to_string()),
                }),
            ))
        }
    }
}

/// GET /api/v1/attachments/:id — Download an attachment.
pub async fn download_attachment(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Path(id): Path<String>,
) -> Result<Response<Body>, (StatusCode, Json<ErrorResponse>)> {
    require_scope(&api_key, "agent")?;

    let record = match state.factories.attachment.get_meta(&id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Attachment not found".to_string(),
                    detail: Some(format!("No attachment with ID '{}'", id)),
                }),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    };

    // Check permission
    match state
        .factories
        .attachment
        .consume_download(&id, &api_key.email_address)
        .await
    {
        Ok(()) => {}
        Err(e) => {
            state.metrics.inc_attachment_unauthorized_access();
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Download not authorized".to_string(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    }

    // Compute file path from sender_email and attachment_id.
    // Extension comes from the single derivation entry point — must match
    // the save side ("bin" for extensionless filenames).
    let ext = AttachmentFactory::extension_for(&record.filename);
    let file_path = state
        .factories
        .attachment
        .file_path(&record.sender_email, &id, ext);

    match AttachmentFactory::open_attachment(&file_path).await {
        Ok(file) => {
            state.metrics.inc_attachments_downloaded();
            let content_type = record
                .content_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let filename = record.filename.clone();

            // Get file size for Content-Length
            let metadata = match file.metadata().await {
                Ok(m) => m,
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to read attachment metadata".to_string(),
                            detail: Some(e.to_string()),
                        }),
                    ));
                }
            };
            let file_size = metadata.len();

            info!(
                operation = "attachment_downloaded",
                attachment_id = %id,
                filename = %filename,
                size = file_size,
                "Attachment downloaded (streaming)"
            );

            let stream = tokio_util::io::ReaderStream::new(file);
            let body = Body::from_stream(stream);

            let response = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", &content_type)
                .header(
                    "Content-Disposition",
                    // AUDIT-1 P2-6: sanitize the filename — strip control chars
                    // (CR/LF header injection) and replace quotes that would
                    // break the header value (malicious names caused a panic).
                    format!(
                        "attachment; filename=\"{}\"",
                        filename
                            .chars()
                            .filter(|c| !c.is_control())
                            .collect::<String>()
                            .replace('"', "'")
                    ),
                )
                .header("Content-Length", file_size.to_string())
                .body(body)
                .unwrap();

            Ok(response)
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to read attachment file".to_string(),
                detail: Some(e.to_string()),
            }),
        )),
    }
}
