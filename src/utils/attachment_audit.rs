use actix_web::HttpRequest;
use serde_json::json;

use crate::model::audit_log_model::AuditLog;
use crate::utils::client_ip::client_ip_from_http_request;
use crate::utils::db::get_db;

pub async fn log_attachment_upload(
    req: &HttpRequest,
    user_id: &str,
    path: &str,
    context_type: &str,
    context_id: &str,
    file_size: u64,
) {
    let client_ip = client_ip_from_http_request(req);
    let db = get_db();
    if let Err(e) = AuditLog::insert(
        &db,
        "attachment.upload",
        Some("attachment"),
        Some(path),
        json!({
            "userId": user_id,
            "contextType": context_type,
            "contextId": context_id,
            "fileSize": file_size,
        }),
        Some(&client_ip),
    )
    .await
    {
        log::warn!("Failed to write attachment upload audit log ({path}): {e}");
    }
}

pub async fn log_attachment_access(
    req: &HttpRequest,
    user_id: &str,
    path: &str,
    access_kind: &str,
) {
    let client_ip = client_ip_from_http_request(req);
    let db = get_db();
    if let Err(e) = AuditLog::insert(
        &db,
        "attachment.access",
        Some("attachment"),
        Some(path),
        json!({
            "userId": user_id,
            "kind": access_kind,
        }),
        Some(&client_ip),
    )
    .await
    {
        log::warn!("Failed to write attachment audit log ({path}): {e}");
    }
}
